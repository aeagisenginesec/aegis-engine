// Package arm implements ir.Adapter for Azure Resource Manager templates
// (JSON) and, via the bicep adapter, Bicep files compiled to ARM.
//
// Strategy: convert ARM resources into the canonical IR using
// Terraform-style resource types and snake_case attribute names, so the
// entire existing Azure rule pack (313 rules) applies without writing new
// rules.
//
//   - Microsoft.Storage/storageAccounts/myaccount ->
//     ir.Resource{Type: "azurerm_storage_account", Name: "myaccount"}
//   - camelCase properties are converted to snake_case recursively, with
//     per-type renames for properties whose Terraform names differ
//     (e.g. allowBlobPublicAccess -> allow_blob_public_access).
//   - ARM template functions ([parameters('x')], [variables('y')],
//     [concat(...)], ...) are resolved where static; anything else becomes
//     an explicit Unknown value (never guessed).
//   - parameters without defaults are unknown by design.
//
// Detection: Handles() sniffs file content for the ARM deployment template
// $schema marker because the manifests adapter claims every .json file.
// This adapter must be registered BEFORE manifests.Adapter in
// defaultAdapters().
package arm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// Adapter parses ARM JSON templates into the canonical IR.
type Adapter struct{}

// Compile-time check that Adapter satisfies ir.Adapter.
var _ ir.Adapter = Adapter{}

// Compile-time check that Adapter satisfies ir.ContentSniffer.
var _ ir.ContentSniffer = Adapter{}

// New constructs the adapter.
func New() *Adapter { return &Adapter{} }

// Name identifies the adapter.
func (Adapter) Name() string { return "arm" }

// Handles reports whether the file looks like an ARM deployment template:
// a .json file whose content carries the ARM deploymentTemplate $schema.
func (Adapter) Handles(path string) bool {
	if !strings.EqualFold(filepath.Ext(path), ".json") {
		return false
	}
	// .plan.json belongs to the planjson adapter.
	if strings.HasSuffix(strings.ToLower(path), ".plan.json") {
		return false
	}
	src, err := readBounded(path, 64<<10) // 64 KiB is plenty for a $schema scan
	if err != nil {
		return false
	}
	return Adapter{}.HandlesContent(path, src)
}

// HandlesContent is the content-aware form of Handles for pipelines that
// already hold the file bytes (in-memory API scans): same extension gate,
// sniffing the provided bytes instead of reading from disk.
func (Adapter) HandlesContent(path string, src []byte) bool {
	if !strings.EqualFold(filepath.Ext(path), ".json") {
		return false
	}
	// .plan.json belongs to the planjson adapter.
	if strings.HasSuffix(strings.ToLower(path), ".plan.json") {
		return false
	}
	return looksLikeARMContent(src)
}

// looksLikeARMContent checks bytes for the ARM deployment template marker.
func looksLikeARMContent(src []byte) bool {
	// The canonical marker: "$schema": ".../deploymentTemplate.json#"
	// Case-insensitive match on the schema file name.
	lower := strings.ToLower(string(src))
	return strings.Contains(lower, "deploymenttemplate.json")
}

// readBounded reads at most n bytes from path.
func readBounded(path string, n int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, n)
	m, err := f.Read(buf)
	if err != nil && m == 0 {
		return nil, err
	}
	return buf[:m], nil
}

// Parse converts an ARM template into IR resources. Malformed JSON becomes
// an error diagnostic; content problems never produce a hard error.
func (Adapter) Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error) {
	var tmpl map[string]any
	if err := json.Unmarshal(src, &tmpl); err != nil {
		return nil, []ir.Diagnostic{{
			Level:   "error",
			Message: fmt.Sprintf("arm: invalid JSON in %s: %v", path, err),
			Span:    ir.Span{File: path},
		}}, nil
	}
	resources, diags := BuildResources(path, tmpl)
	return resources, diags, nil
}

// template holds the decoded sections of one ARM template.
type template struct {
	path      string
	params    map[string]paramDef
	variables map[string]any
	span      ir.Span
	diags     []ir.Diagnostic
}

type paramDef struct {
	def     ir.Value // default value, or Unknown when none
	rawType string
}

// BuildResources converts a decoded ARM template document into IR
// resources. Exported so the bicep adapter can reuse it after translating
// Bicep syntax into ARM-equivalent structures.
func BuildResources(path string, tmpl map[string]any) ([]ir.Resource, []ir.Diagnostic) {
	t := &template{
		path:      path,
		params:    map[string]paramDef{},
		variables: map[string]any{},
		span:      ir.Span{File: path, StartLine: 1, StartCol: 1},
	}
	// Parameters first: name -> default (unknown when absent).
	if pm, ok := tmpl["parameters"].(map[string]any); ok {
		for name, pv := range pm {
			def := ir.UnknownValue(t.span)
			rawType := ""
			if pdm, ok := pv.(map[string]any); ok {
				if typ, ok := pdm["type"].(string); ok {
					rawType = typ
				}
				if d, ok := pdm["defaultValue"]; ok {
					def = t.staticValue(d)
				}
			}
			t.params[name] = paramDef{def: def, rawType: rawType}
		}
	}
	// Variables: evaluated lazily with cycle protection.
	if vm, ok := tmpl["variables"].(map[string]any); ok {
		for name, v := range vm {
			t.variables[name] = v
		}
	}
	rawList, _ := tmpl["resources"].([]any)
	// Deterministic order: sort by type+name.
	sort.SliceStable(rawList, func(i, j int) bool {
		ti, _ := rawList[i].(map[string]any)["type"].(string)
		tj, _ := rawList[j].(map[string]any)["type"].(string)
		if ti != tj {
			return ti < tj
		}
		ni, _ := rawList[i].(map[string]any)["name"].(string)
		nj, _ := rawList[j].(map[string]any)["name"].(string)
		return ni < nj
	})
	ctx := &evalCtx{t: t, varStack: map[string]bool{}}
	var out []ir.Resource
	for _, rv := range rawList {
		rdm, ok := rv.(map[string]any)
		if !ok {
			t.diag("warning", "arm: resource entry is not an object; skipped")
			continue
		}
		// ARM copy loops: explicit diagnostic, resource skipped (never
		// silently half-expanded).
		if _, hasCopy := rdm["copy"]; hasCopy {
			name, _ := rdm["name"].(string)
			t.diag("warning", fmt.Sprintf("arm: resource %q uses a copy loop which is not expanded; skipped", name))
			continue
		}
		armType, _ := rdm["type"].(string)
		if armType == "" {
			t.diag("warning", "arm: resource without type; skipped")
			continue
		}
		tfType, mapped := normalizeType(armType)
		if !mapped {
			t.diag("warning", fmt.Sprintf("arm: unmapped resource type %q; emitted as %q (no rules apply)", armType, tfType))
		}
		name := ctx.eval(rdm["name"])
		nameStr, ok := name.AsString()
		if !ok {
			nameStr, _ = rdm["name"].(string)
			if nameStr == "" {
				nameStr = "unnamed"
			}
		}
		res := ir.Resource{
			Type:       tfType,
			Name:       nameStr,
			Provider:   "azure",
			Attributes: map[string]ir.Value{},
			Span:       t.span,
		}
		ctx.mapResource(res, rdm)
		out = append(out, res)
	}
	out = foldBlobServices(out, t)
	out = foldQueueServices(out, t)
	out = translateStorageBlocks(out)
	out = translateVNetDNS(out)
	return out, t.diags
}

func (t *template) diag(level, msg string) {
	t.diags = append(t.diags, ir.Diagnostic{Level: level, Message: msg, Span: t.span})
}

// staticValue converts a parameter default to an ir.Value. Non-scalars and
// ARM expressions are evaluated (expressions may reference other params).
func (t *template) staticValue(v any) ir.Value {
	ctx := &evalCtx{t: t, varStack: map[string]bool{}}
	return ctx.eval(v)
}

// evalCtx carries evaluation state for ARM template functions.
type evalCtx struct {
	t        *template
	varStack map[string]bool // cycle guard for variables
	warned   map[string]bool // dedup for one-time expression warnings
	// varCache memoizes fully-evaluated variable values. Without it,
	// variables('vN') chains re-evaluate exponentially: v22 = concat of
	// v21 twice costs 2^22 leaf evaluations (~18 s from a 2 KB file).
	// Cache entries are only stored when the evaluation saw no cycle-
	// guard hit (cycleHits unchanged across it): a value computed while
	// a dependency was in-progress embeds an Unknown that a later,
	// cycle-free evaluation would not produce (coalesce() skips
	// Unknowns), so poisoned evaluations must never be cached.
	varCache map[string]ir.Value
	// cycleHits counts variables() lookups that hit an in-progress
	// variable (the cycle guard). A counter, not a bool: a sticky bool
	// would make later evaluations' "unchanged" snapshots pass even
	// when a NEW hit occurred during them, caching poisoned values.
	cycleHits int
}

// maxConstructedString caps strings built by concat/join/format/replace.
// Variable chains can otherwise double a string per level (v30 = 8 GiB
// from a 2 KB file) even with memoization, because the final string
// itself is that large. Literals from the file are unaffected (bounded
// by the file-size cap); only constructed amplification is capped.
const maxConstructedString = 1 << 20

// eval resolves a raw template value to an ir.Value. Strings in [..] are
// ARM expressions; everything else converts literally.
func (c *evalCtx) eval(v any) ir.Value {
	span := c.t.span
	switch tv := v.(type) {
	case nil:
		return ir.UnknownValue(span)
	case bool:
		return ir.Value{Raw: tv, Known: true, Span: span}
	case string:
		if isExpression(tv) {
			return c.evalExpression(tv)
		}
		return ir.Value{Raw: tv, Known: true, Span: span}
	case float64:
		return ir.Value{Raw: tv, Known: true, Span: span}
	case json.Number:
		if f, err := tv.Float64(); err == nil {
			return ir.Value{Raw: f, Known: true, Span: span}
		}
		return ir.UnknownValue(span)
	case []any:
		out := make([]ir.Value, 0, len(tv))
		for _, e := range tv {
			out = append(out, c.eval(e))
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case map[string]any:
		out := make(map[string]ir.Value, len(tv))
		for k, e := range tv {
			out[snake(k)] = c.eval(e)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	default:
		return ir.UnknownValue(span)
	}
}

// isExpression reports whether s is an ARM template expression: [..]
// with [[ as the escape for a literal leading bracket.
func isExpression(s string) bool {
	if len(s) < 2 || s[0] != '[' || s[1] == '[' {
		return false
	}
	return strings.HasSuffix(strings.TrimSpace(s), "]")
}

// unescapeBracket handles the [[ escape for a literal [.
func unescapeBracket(s string) (string, bool) {
	if strings.HasPrefix(s, "[[") {
		return "[" + s[2:], true
	}
	return s, false
}

// evalExpression parses and evaluates one ARM [...] expression.
// warnOnce emits a template diagnostic at most once per key within one
// template parse, so a repeated unsupported expression does not flood
// the scan output.
func (c *evalCtx) warnOnce(key, msg string) {
	if c.warned == nil {
		c.warned = map[string]bool{}
	}
	if c.warned[key] {
		return
	}
	c.warned[key] = true
	c.t.diag("warning", msg)
}

func (c *evalCtx) evalExpression(s string) ir.Value {
	span := c.t.span
	if lit, ok := unescapeBracket(s); ok {
		return ir.Value{Raw: lit, Known: true, Span: span}
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	v, ok := c.parseExpr(inner)
	if !ok {
		// Unparsable expression: the value is Unknown, and the failure
		// must be visible — a property guarded by an unparsed
		// expression would otherwise fail silently.
		c.warnOnce("expr:"+s, fmt.Sprintf("arm: could not parse expression %q; treated as unknown", s))
		return ir.UnknownValue(span)
	}
	return v
}

// --- tiny recursive-descent parser for ARM expressions ---

type exprParser struct {
	s   string
	pos int
	ctx *evalCtx
}

func (c *evalCtx) parseExpr(s string) (ir.Value, bool) {
	p := &exprParser{s: s, ctx: c}
	v, ok := p.parseValue()
	if !ok {
		return ir.Value{}, false
	}
	p.skipWS()
	if p.pos != len(p.s) {
		return ir.Value{}, false // trailing garbage
	}
	return v, true
}

func (p *exprParser) skipWS() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t' || p.s[p.pos] == '\n' || p.s[p.pos] == '\r') {
		p.pos++
	}
}

func (p *exprParser) parseValue() (ir.Value, bool) {
	p.skipWS()
	if p.pos >= len(p.s) {
		return ir.Value{}, false
	}
	ch := p.s[p.pos]
	span := p.ctx.t.span
	switch {
	case ch == '\'':
		s, ok := p.parseString()
		if !ok {
			return ir.Value{}, false
		}
		return ir.Value{Raw: s, Known: true, Span: span}, true
	case ch == '-' || (ch >= '0' && ch <= '9'):
		n, ok := p.parseNumber()
		if !ok {
			return ir.Value{}, false
		}
		return ir.Value{Raw: n, Known: true, Span: span}, true
	case strings.HasPrefix(p.s[p.pos:], "true") && !isIdentChar(peekAt(p.s, p.pos+4)):
		p.pos += 4
		return ir.Value{Raw: true, Known: true, Span: span}, true
	case strings.HasPrefix(p.s[p.pos:], "false") && !isIdentChar(peekAt(p.s, p.pos+5)):
		p.pos += 5
		return ir.Value{Raw: false, Known: true, Span: span}, true
	case strings.HasPrefix(p.s[p.pos:], "null") && !isIdentChar(peekAt(p.s, p.pos+4)):
		p.pos += 4
		return ir.UnknownValue(span), true
	case isIdentStart(ch):
		return p.parseCallOrRef()
	}
	return ir.Value{}, false
}

func isIdentStart(ch byte) bool {
	return ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}
func isIdentChar(ch byte) bool { return isIdentStart(ch) || (ch >= '0' && ch <= '9') }
func peekAt(s string, i int) byte {
	if i >= len(s) {
		return 0
	}
	return s[i]
}

func (p *exprParser) parseIdent() string {
	start := p.pos
	for p.pos < len(p.s) && isIdentChar(p.s[p.pos]) {
		p.pos++
	}
	return p.s[start:p.pos]
}

func (p *exprParser) parseString() (string, bool) {
	// ARM strings use '' to escape a quote.
	var b strings.Builder
	p.pos++ // opening '
	for p.pos < len(p.s) {
		ch := p.s[p.pos]
		if ch == '\'' {
			if peekAt(p.s, p.pos+1) == '\'' {
				b.WriteByte('\'')
				p.pos += 2
				continue
			}
			p.pos++
			return b.String(), true
		}
		b.WriteByte(ch)
		p.pos++
	}
	return "", false
}

func (p *exprParser) parseNumber() (float64, bool) {
	start := p.pos
	if p.s[p.pos] == '-' {
		p.pos++
	}
	for p.pos < len(p.s) && ((p.s[p.pos] >= '0' && p.s[p.pos] <= '9') || p.s[p.pos] == '.') {
		p.pos++
	}
	f, err := strconv.ParseFloat(p.s[start:p.pos], 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// parseCallOrRef parses ident(args) or a bare identifier path with
// .prop / [index] suffixes.
func (p *exprParser) parseCallOrRef() (ir.Value, bool) {
	name := p.parseIdent()
	p.skipWS()
	span := p.ctx.t.span
	if p.pos < len(p.s) && p.s[p.pos] == '(' {
		p.pos++
		var args []ir.Value
		p.skipWS()
		if p.pos < len(p.s) && p.s[p.pos] != ')' {
			for {
				a, ok := p.parseValue()
				if !ok {
					return ir.Value{}, false
				}
				args = append(args, a)
				p.skipWS()
				if p.pos < len(p.s) && p.s[p.pos] == ',' {
					p.pos++
					continue
				}
				break
			}
		}
		p.skipWS()
		if p.pos >= len(p.s) || p.s[p.pos] != ')' {
			return ir.Value{}, false
		}
		p.pos++
		v := p.ctx.callFunc(name, args)
		return p.applySuffixes(v)
	}
	// Bare identifier: not a valid ARM expression element on its own.
	_ = span
	return ir.Value{}, false
}

// applySuffixes handles .prop and [n] / ['k'] accessors after a call.
func (p *exprParser) applySuffixes(v ir.Value) (ir.Value, bool) {
	span := p.ctx.t.span
	for {
		p.skipWS()
		if p.pos >= len(p.s) {
			return v, true
		}
		switch p.s[p.pos] {
		case '.':
			p.pos++
			prop := p.parseIdent()
			if prop == "" {
				return ir.Value{}, false
			}
			v = navigate(v, prop, span)
		case '[':
			p.pos++
			p.skipWS()
			if p.pos < len(p.s) && p.s[p.pos] == '\'' {
				key, ok := p.parseString()
				if !ok {
					return ir.Value{}, false
				}
				p.skipWS()
				if p.pos >= len(p.s) || p.s[p.pos] != ']' {
					return ir.Value{}, false
				}
				p.pos++
				v = navigate(v, key, span)
			} else {
				idx, ok := p.parseNumber()
				if !ok {
					return ir.Value{}, false
				}
				p.skipWS()
				if p.pos >= len(p.s) || p.s[p.pos] != ']' {
					return ir.Value{}, false
				}
				p.pos++
				v = navigateIndex(v, int(idx), span)
			}
		default:
			return v, true
		}
		// Once unknown (!v.Known), remaining suffixes keep it
		// unknown; they are still consumed for parse validity.
	}
}

// navigate resolves .prop on a known map value; anything else -> Unknown.
func navigate(v ir.Value, prop string, span ir.Span) ir.Value {
	if !v.Known {
		return ir.Value{Known: false, Span: span}
	}
	if m, ok := v.Raw.(map[string]ir.Value); ok {
		if e, ok := m[prop]; ok {
			return e
		}
	}
	return ir.Value{Known: false, Span: span}
}

// navigateIndex resolves [n] on a known list value.
func navigateIndex(v ir.Value, idx int, span ir.Span) ir.Value {
	if !v.Known {
		return ir.Value{Known: false, Span: span}
	}
	if l, ok := v.Raw.([]ir.Value); ok && idx >= 0 && idx < len(l) {
		return l[idx]
	}
	return ir.Value{Known: false, Span: span}
}

// callFunc evaluates the supported ARM template functions. Anything not
// explicitly handled returns Unknown (never guessed).
func (c *evalCtx) callFunc(name string, args []ir.Value) ir.Value {
	span := c.t.span
	unknown := ir.Value{Known: false, Span: span}
	strArg := func(i int) (string, bool) {
		if i >= len(args) {
			return "", false
		}
		return args[i].AsString()
	}
	switch strings.ToLower(name) {
	case "parameters":
		n, ok := strArg(0)
		if !ok {
			return unknown
		}
		if p, ok := c.t.params[n]; ok {
			return p.def
		}
		return unknown
	case "variables":
		n, ok := strArg(0)
		if !ok {
			return unknown
		}
		if cached, ok := c.varCache[n]; ok {
			return cached
		}
		if c.varStack[n] {
			c.cycleHits++
			return unknown // cycle
		}
		raw, ok := c.t.variables[n]
		if !ok {
			return unknown
		}
		c.varStack[n] = true
		before := c.cycleHits
		v := c.eval(raw)
		delete(c.varStack, n)
		// Cache only cycle-free evaluations (see varCache doc).
		if c.cycleHits == before {
			if c.varCache == nil {
				c.varCache = map[string]ir.Value{}
			}
			c.varCache[n] = v
		}
		return v
	case "concat":
		var b strings.Builder
		for _, a := range args {
			s, ok := a.AsString()
			if !ok {
				return unknown
			}
			if b.Len()+len(s) > maxConstructedString {
				return unknown // constructed string would exceed cap
			}
			b.WriteString(s)
		}
		return ir.Value{Raw: b.String(), Known: true, Span: span}
	case "format":
		f, ok := strArg(0)
		if !ok {
			return unknown
		}
		out := f
		for i := 1; i < len(args); i++ {
			s, ok := args[i].AsString()
			if !ok {
				return unknown
			}
			out = strings.ReplaceAll(out, "{"+strconv.Itoa(i-1)+"}", s)
			if len(out) > maxConstructedString {
				return unknown // constructed string would exceed cap
			}
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case "tolower":
		s, ok := strArg(0)
		if !ok {
			return unknown
		}
		return ir.Value{Raw: strings.ToLower(s), Known: true, Span: span}
	case "toupper":
		s, ok := strArg(0)
		if !ok {
			return unknown
		}
		return ir.Value{Raw: strings.ToUpper(s), Known: true, Span: span}
	case "replace":
		s, ok1 := strArg(0)
		old, ok2 := strArg(1)
		neu, ok3 := strArg(2)
		if !ok1 || !ok2 || !ok3 {
			return unknown
		}
		// ReplaceAll can amplify (short old -> long neu, many matches).
		if old != "" && len(neu) > len(old) {
			if n := strings.Count(s, old); n > 0 && len(s)+n*(len(neu)-len(old)) > maxConstructedString {
				return unknown
			}
		}
		return ir.Value{Raw: strings.ReplaceAll(s, old, neu), Known: true, Span: span}
	case "string":
		if len(args) == 0 {
			return unknown
		}
		a := args[0]
		if !a.Known {
			return unknown
		}
		switch tv := a.Raw.(type) {
		case string:
			return ir.Value{Raw: tv, Known: true, Span: span}
		case bool:
			return ir.Value{Raw: strconv.FormatBool(tv), Known: true, Span: span}
		case float64:
			return ir.Value{Raw: strconv.FormatFloat(tv, 'f', -1, 64), Known: true, Span: span}
		}
		return unknown
	case "int":
		s, ok := strArg(0)
		if !ok {
			// maybe already a number
			if len(args) > 0 {
				if f, ok := args[0].Raw.(float64); ok && args[0].Known {
					return ir.Value{Raw: f, Known: true, Span: span}
				}
			}
			return unknown
		}
		if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
			return ir.Value{Raw: f, Known: true, Span: span}
		}
		return unknown
	case "bool":
		s, ok := strArg(0)
		if !ok {
			if len(args) > 0 {
				if b, ok := args[0].Raw.(bool); ok && args[0].Known {
					return ir.Value{Raw: b, Known: true, Span: span}
				}
			}
			return unknown
		}
		if b, err := strconv.ParseBool(strings.TrimSpace(s)); err == nil {
			return ir.Value{Raw: b, Known: true, Span: span}
		}
		return unknown
	case "createarray":
		out := make([]ir.Value, 0, len(args))
		for _, a := range args {
			if !a.Known {
				return unknown
			}
			out = append(out, a)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case "coalesce":
		for _, a := range args {
			if a.Known && a.Raw != nil {
				return a
			}
		}
		return unknown
	case "empty":
		if len(args) == 0 || !args[0].Known {
			return unknown
		}
		switch tv := args[0].Raw.(type) {
		case string:
			return ir.Value{Raw: tv == "", Known: true, Span: span}
		case []ir.Value:
			return ir.Value{Raw: len(tv) == 0, Known: true, Span: span}
		case map[string]ir.Value:
			return ir.Value{Raw: len(tv) == 0, Known: true, Span: span}
		}
		return unknown
	case "length":
		if len(args) == 0 || !args[0].Known {
			return unknown
		}
		switch tv := args[0].Raw.(type) {
		case string:
			return ir.Value{Raw: float64(len(tv)), Known: true, Span: span}
		case []ir.Value:
			return ir.Value{Raw: float64(len(tv)), Known: true, Span: span}
		}
		return unknown
	case "contains":
		if len(args) < 2 || !args[0].Known || !args[1].Known {
			return unknown
		}
		switch tv := args[0].Raw.(type) {
		case string:
			s, ok := args[1].AsString()
			if !ok {
				return unknown
			}
			return ir.Value{Raw: strings.Contains(tv, s), Known: true, Span: span}
		case []ir.Value:
			s, ok := args[1].AsString()
			if !ok {
				return unknown
			}
			for _, e := range tv {
				if es, ok := e.AsString(); ok && es == s {
					return ir.Value{Raw: true, Known: true, Span: span}
				}
			}
			return ir.Value{Raw: false, Known: true, Span: span}
		}
		return unknown
	case "startswith":
		a, ok1 := strArg(0)
		b, ok2 := strArg(1)
		if !ok1 || !ok2 {
			return unknown
		}
		return ir.Value{Raw: strings.HasPrefix(a, b), Known: true, Span: span}
	case "endswith":
		a, ok1 := strArg(0)
		b, ok2 := strArg(1)
		if !ok1 || !ok2 {
			return unknown
		}
		return ir.Value{Raw: strings.HasSuffix(a, b), Known: true, Span: span}
	case "split":
		a, ok1 := strArg(0)
		b, ok2 := strArg(1)
		if !ok1 || !ok2 {
			return unknown
		}
		parts := strings.Split(a, b)
		out := make([]ir.Value, 0, len(parts))
		for _, p := range parts {
			out = append(out, ir.Value{Raw: p, Known: true, Span: span})
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case "join":
		if len(args) < 2 || !args[0].Known {
			return unknown
		}
		l, ok := args[0].Raw.([]ir.Value)
		if !ok {
			return unknown
		}
		sep, ok := strArg(1)
		if !ok {
			return unknown
		}
		parts := make([]string, 0, len(l))
		total := len(sep) * len(l)
		for _, e := range l {
			s, ok := e.AsString()
			if !ok {
				return unknown
			}
			total += len(s)
			if total > maxConstructedString {
				return unknown // constructed string would exceed cap
			}
			parts = append(parts, s)
		}
		return ir.Value{Raw: strings.Join(parts, sep), Known: true, Span: span}
	case "first", "last":
		if len(args) == 0 || !args[0].Known {
			return unknown
		}
		switch tv := args[0].Raw.(type) {
		case []ir.Value:
			if len(tv) == 0 {
				return unknown
			}
			if strings.ToLower(name) == "first" {
				return tv[0]
			}
			return tv[len(tv)-1]
		case string:
			if tv == "" {
				return unknown
			}
			if strings.ToLower(name) == "first" {
				return ir.Value{Raw: string(tv[0]), Known: true, Span: span}
			}
			return ir.Value{Raw: string(tv[len(tv)-1]), Known: true, Span: span}
		}
		return unknown
	case "resourceid":
		// resourceId('Microsoft.Storage/storageAccounts', 'name', ...)
		// with all-literal arguments statically names a resource in
		// this template, even though the full Azure resource ID
		// string cannot be constructed here: surface it as a
		// reference so cross-resource rules (private-endpoint
		// linkage, role assignments) can correlate the resources.
		// Non-literal arguments stay Unknown.
		if len(args) < 2 {
			return unknown
		}
		strs := make([]string, len(args))
		for i, a := range args {
			s, ok := a.Raw.(string)
			if !a.Known || !ok {
				return unknown
			}
			strs[i] = s
		}
		tfType, _ := normalizeType(strs[0])
		return ir.Value{
			Ref:   tfType + "." + strs[len(strs)-1] + ".id",
			Known: true, Span: span,
		}
	}
	// Everything else (reference, listKeys, subscription(),
	// resourceGroup(), if(), equals(), guid(), uniqueString(), utcNow(),
	// providers(), extensionResourceId(), ...) -> explicit Unknown.
	// Known-but-unresolvable functions stay silent: their values
	// genuinely cannot be decided statically. A function name outside
	// the known ARM set is almost certainly a typo or an unsupported
	// construct, so it gets one warning per template parse — otherwise
	// a property guarded by it would fail silently.
	if !knownARMFunction(name) {
		c.warnOnce("func:"+strings.ToLower(name), fmt.Sprintf("arm: unknown template function %q; treated as unknown", name))
	}
	return unknown
}

// knownARMFunction reports whether name is a function from the ARM
// template function reference (implemented or known-unresolvable). The
// list is generous: a false warning on a real function is noise, while
// a missed typo is a silent miss. list* is matched by prefix: the
// family (listKeys, listAccountSas, listSecrets, ...) is too large to
// enumerate.
func knownARMFunction(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "list") {
		return true
	}
	switch lower {
	case "abs", "add", "and", "array", "base64", "base64tojson",
		"base64tostring", "builduri", "cidrhost", "cidrsubnet", "ceil",
		"copyindex", "datauri", "datauritostring", "datetimeadd",
		"datetimefromepoch", "datetimetoepoch", "datetimetoutc",
		"deployment", "div", "empty", "environment", "equals",
		"extensionconfig", "extensionresourceid", "field", "filter",
		"flatten", "float", "floor", "format", "greater",
		"greaterorequals", "groupby", "guid", "if", "indexof",
		"intersection", "items", "json", "lambda", "lambdavariables",
		"less", "lessorequals", "managementgroup",
		"managementgroupresourceid", "map", "mod", "mul",
		"newguid", "not", "objectkeys", "or", "parsecidr", "pickzones",
		"providers", "range", "reduce", "reference", "references",
		"resourcegroup", "resourceid", "reverse", "shallowmerge", "sort",
		"sub", "subscription", "subscriptionresourceid", "tenant",
		"tenantresourceid", "toobject", "tryget",
		"tryindexfromend", "utcnow", "uniquestring", "uri",
		"uricomponent", "uricomponenttostring",
		// Bicep-side functions / placeholders that legitimately reach
		// the ARM evaluator: getSecret (Key Vault references),
		// load* (compile-time file loads), and "unknown" — the Bicep
		// adapter's own Unknown placeholder ([unknown()]).
		"getsecret", "loadtextcontent", "loadfileasbase64",
		"loadjsoncontent", "loadyamlcontent", "unknown":
		return true
	}
	return false
}

// mapResource converts one ARM resource's fields into IR attributes:
// top-level fields (location, tags, kind, sku, identity) plus the
// properties object flattened with per-type renames.
// mergeDdosProtectionPlan combines the two ARM VNet properties
// enableDdosProtection (bool) and ddosProtectionPlan ({id}) into the
// single Terraform block value ddos_protection_plan { id, enable }
// the Azure rules read. Only the facts present in the template are
// carried: no enable is invented when the template omits the flag.
// Returns false when neither property is present.
func mergeDdosProtectionPlan(c *evalCtx, props map[string]any) (ir.Value, bool) {
	planRaw, hasPlan := props["ddosProtectionPlan"]
	enRaw, hasEnable := props["enableDdosProtection"]
	if !hasPlan && !hasEnable {
		return ir.Value{}, false
	}
	fields := map[string]ir.Value{}
	span := c.t.span
	if hasPlan {
		pv := c.eval(planRaw)
		span = pv.Span
		if m, ok := pv.AsMap(); ok {
			for k, fv := range m {
				fields[snake(k)] = fv
			}
		} else {
			// Non-object plan value (bare reference): keep it as id.
			fields["id"] = pv
		}
	}
	if hasEnable {
		fields["enable"] = c.eval(enRaw)
	}
	if len(fields) == 0 {
		return ir.Value{}, false
	}
	return ir.Value{Raw: fields, Known: true, Span: span}, true
}

func (c *evalCtx) mapResource(res ir.Resource, rdm map[string]any) {
	span := c.t.span
	if v, ok := rdm["location"]; ok {
		res.Attributes["location"] = c.eval(v)
	}
	if v, ok := rdm["tags"]; ok {
		res.Attributes["tags"] = c.eval(v)
	}
	if v, ok := rdm["kind"]; ok {
		res.Attributes["kind"] = c.eval(v)
	}
	if v, ok := rdm["sku"]; ok {
		sv := c.eval(v)
		res.Attributes["sku"] = sv
		// Rules sometimes read sku as a plain string; expose sku.name too.
		if m, ok := sv.AsMap(); ok {
			if n, ok := m["name"]; ok {
				res.Attributes["sku_name"] = n
			}
		}
	}
	if v, ok := rdm["identity"]; ok {
		res.Attributes["identity"] = c.eval(v)
		if m, ok := res.Attributes["identity"].AsMap(); ok {
			if t, ok := m["type"]; ok {
				res.Attributes["identity_type"] = t
			}
		}
	}
	props, _ := rdm["properties"].(map[string]any)
	if props == nil {
		props = map[string]any{}
	}
	renames := propertyRenames(res.Type)
	// Merge the ARM VNet DDoS pair into the single TF block
	// ddos_protection_plan { id, enable } BEFORE the generic loop.
	// The two ARM properties collide on that one IR name —
	// enableDdosProtection via the rename table, ddosProtectionPlan
	// via snake_case — and the loop's first-writer-wins guard made
	// the winner a coin flip on Go map iteration order: when the
	// plan object won, AEGIS-AZURE-057 saw a block with no enable
	// and fired on compliant VNets (intermittent compliant-gate
	// failure); when the bare bool won, the rule could not decide
	// at all. Pre-setting the merged block makes the loop skip both
	// source keys deterministically.
	if res.Type == "azurerm_virtual_network" {
		if merged, ok := mergeDdosProtectionPlan(c, props); ok {
			res.Attributes["ddos_protection_plan"] = merged
		}
	}
	for k, v := range props {
		var name string
		if rn, ok := renames[k]; ok {
			name = rn
		} else {
			name = snake(k)
		}
		// Avoid clobbering top-level fields already set.
		if _, exists := res.Attributes[name]; exists {
			continue
		}
		res.Attributes[name] = c.eval(v)
	}
	// Promote nested encryption.requireInfrastructureEncryption to the
	// top-level infrastructure_encryption_enabled the Azure rules expect.
	// ARM nests it as properties.encryption.requireInfrastructureEncryption.
	if res.Type == "azurerm_storage_account" {
		if _, exists := res.Attributes["infrastructure_encryption_enabled"]; !exists {
			if enc, ok := res.Attributes["encryption"]; ok {
				if m, ok := enc.AsMap(); ok {
					for ek, ev := range m {
						if ek == "requireInfrastructureEncryption" || ek == "require_infrastructure_encryption" {
							res.Attributes["infrastructure_encryption_enabled"] = ev
							break
						}
					}
				}
			}
		}
	}
	// Promote nested network.publicNetworkAccess to the top level for
	// PostgreSQL flexible servers. ARM nests it as
	// properties.network.publicNetworkAccess, while the TF attribute
	// (and AEGIS-AZURE-169) is the flat public_network_access_enabled.
	// Without this promotion the property was invisible to the rules,
	// so AZURE-169 fired on "absence" even when the template explicitly
	// set publicNetworkAccess to "Disabled" (17 of 18 R5 firings).
	if res.Type == "azurerm_postgresql_flexible_server" {
		_, hasEnabled := res.Attributes["public_network_access_enabled"]
		_, hasPlain := res.Attributes["public_network_access"]
		if !hasEnabled && !hasPlain {
			if net, ok := res.Attributes["network"]; ok {
				if m, ok := net.AsMap(); ok {
					for ek, ev := range m {
						if ek == "publicNetworkAccess" || ek == "public_network_access" {
							res.Attributes["public_network_access"] = ev
							break
						}
					}
				}
			}
		}
	}
	// Convert the ARM publicNetworkAccess enum to the boolean
	// public_network_access_enabled the TF rules expect, for every
	// resource type (this used to be mssql-only, which left the string
	// enum unreadable — getBool reports it unknown — for all other
	// types). ARM uses "Enabled"/"Disabled". Depending on the
	// per-type renames, the property lands either under
	// public_network_access_enabled (renamed types) or under the
	// generic snake_case name public_network_access.
	for _, key := range []string{"public_network_access_enabled", "public_network_access"} {
		v, ok := res.Attributes[key]
		if !ok {
			continue
		}
		s, ok := v.AsString()
		if !ok {
			continue
		}
		switch s {
		case "Enabled":
			res.Attributes["public_network_access_enabled"] = ir.Value{Raw: true, Known: true, Span: v.Span}
		case "Disabled":
			res.Attributes["public_network_access_enabled"] = ir.Value{Raw: false, Known: true, Span: v.Span}
		}
	}
	// Flatten ARM securityRules: [{name, properties: {access, ...}}]
	// into TF-style security_rule: [{name, access, ...}].
	if res.Type == "azurerm_network_security_group" {
		if sr, ok := res.Attributes["security_rule"]; ok {
			if list, ok := sr.AsList(); ok {
				flat := make([]ir.Value, 0, len(list))
				for _, item := range list {
					if m, ok := item.AsMap(); ok {
						nm := map[string]ir.Value{}
						for k, v := range m {
							nm[k] = v
						}
						// Merge nested properties up.
						if pv, ok := m["properties"]; ok {
							if pm, ok := pv.AsMap(); ok {
								renames := propertyRenames("azurerm_network_security_rule")
								for pk, pv2 := range pm {
									var name string
									if rn, ok := renames[pk]; ok {
										name = rn
									} else {
										name = snake(pk)
									}
									nm[name] = pv2
								}
							}
							delete(nm, "properties")
						}
						flat = append(flat, ir.Value{Raw: nm, Known: true, Span: item.Span})
					} else {
						flat = append(flat, item)
					}
				}
				res.Attributes["security_rule"] = ir.Value{Raw: flat, Known: true, Span: sr.Span}
			}
		}
	}
	// Normalize Key Vault network_acls: ARM ipRules: [{value: ...}] and
	// virtualNetworkRules: [{id: ...}] become the plain string lists
	// ip_rules / virtual_network_subnet_ids the Azure rules read (TF
	// shape). Without this, AZURE-205 fires a false positive on vaults
	// that do define IP/VNet allowances.
	if res.Type == "azurerm_key_vault" {
		if nacls, ok := res.Attributes["network_acls"]; ok {
			if m, ok := nacls.AsMap(); ok {
				if ip, ok := m["ip_rules"]; ok {
					if unwrapped, ok := unwrapSingleKeyList(ip, "value"); ok {
						m["ip_rules"] = unwrapped
					}
				}
				if vr, ok := m["virtual_network_rules"]; ok {
					if unwrapped, ok := unwrapSingleKeyList(vr, "id"); ok {
						m["virtual_network_subnet_ids"] = unwrapped
						delete(m, "virtual_network_rules")
					}
				}
			}
		}
	}
	_ = span
}

// unwrapSingleKeyList converts a list of single-key maps [{key: x}, ...]
// to a plain list [x, ...]. Non-map elements or maps without the key
// abort the conversion.
func unwrapSingleKeyList(v ir.Value, key string) (ir.Value, bool) {
	lst, ok := v.AsList()
	if !ok {
		return ir.Value{}, false
	}
	out := make([]ir.Value, 0, len(lst))
	for _, e := range lst {
		em, ok := e.AsMap()
		if !ok {
			return ir.Value{}, false
		}
		ev, ok := em[key]
		if !ok || !ev.Known {
			return ir.Value{}, false
		}
		out = append(out, ev)
	}
	return ir.Value{Raw: out, Known: true, Span: v.Span}, true
}

// findStorageAccount locates the (single) parent storage account in
// the partially built output slice. Folds search the OUTPUT slice, not
// the input: indices into the input go stale as soon as an earlier
// child is dropped, which mis-folded (or panicked on) templates whose
// service children sit between two accounts.
func findStorageAccount(out []ir.Resource, name string) *ir.Resource {
	for i := range out {
		if out[i].Type == "azurerm_storage_account" && out[i].Name == name {
			return &out[i]
		}
	}
	return nil
}

// objectField extracts one field from an object-valued attribute.
func objectField(v ir.Value, key string) (ir.Value, bool) {
	m, ok := v.Raw.(map[string]ir.Value)
	if !ok {
		return ir.Value{}, false
	}
	f, ok := m[key]
	return f, ok
}

// foldBlobServices merges Microsoft.Storage/storageAccounts/blobServices
// child resources into their parent storage account as a blob_properties
// block, so the blob-property rules apply. The child resource itself is
// dropped (it carries no independent security surface).
func foldBlobServices(resources []ir.Resource, t *template) []ir.Resource {
	var out []ir.Resource
	for _, r := range resources {
		if r.Type != "arm_microsoft_storage_storageaccounts_blobservices" &&
			r.Type != "azurerm_storage_account_blob_services" {
			out = append(out, r)
			continue
		}
		// Child name is "<account>/default": find the parent account.
		parentName := r.Name
		if idx := strings.Index(parentName, "/"); idx >= 0 {
			parentName = parentName[:idx]
		}
		parent := findStorageAccount(out, parentName)
		if parent == nil {
			out = append(out, r) // orphan: keep as-is
			continue
		}
		blk := map[string]ir.Value{}
		if v, ok := r.Attributes["is_versioning_enabled"]; ok {
			blk["versioning_enabled"] = v
		}
		if v, ok := r.Attributes["delete_retention_policy"]; ok {
			blk["delete_retention_policy"] = v
		}
		if v, ok := r.Attributes["container_delete_retention_policy"]; ok {
			blk["container_delete_retention_policy"] = v
		}
		if v, ok := r.Attributes["change_feed_enabled"]; ok {
			blk["change_feed_enabled"] = v
		}
		// ARM spells it changeFeed { enabled = ... }: an object, not a
		// flat change_feed_enabled boolean.
		if v, ok := r.Attributes["change_feed"]; ok {
			if en, eok := objectField(v, "enabled"); eok {
				blk["change_feed_enabled"] = en
			}
		}
		if len(blk) > 0 {
			parent.Attributes["blob_properties"] = ir.Value{
				Raw:   []ir.Value{{Raw: blk, Known: true, Span: r.Span}},
				Known: true, Span: r.Span,
			}
		}
		// child dropped
	}
	return out
}

// foldQueueServices merges Microsoft.Storage/storageAccounts/queueServices
// child resources into their parent storage account as a queue_properties
// block (analytics logging + metrics), mirroring foldBlobServices. The
// child resource itself is dropped.
func foldQueueServices(resources []ir.Resource, t *template) []ir.Resource {
	var out []ir.Resource
	for _, r := range resources {
		if r.Type != "arm_microsoft_storage_storageaccounts_queueservices" &&
			r.Type != "azurerm_storage_account_queue_services" {
			out = append(out, r)
			continue
		}
		// Child name is "<account>/default": find the parent account.
		parentName := r.Name
		if idx := strings.Index(parentName, "/"); idx >= 0 {
			parentName = parentName[:idx]
		}
		parent := findStorageAccount(out, parentName)
		if parent == nil {
			out = append(out, r) // orphan: keep as-is
			continue
		}
		blk := map[string]ir.Value{}
		if v, ok := r.Attributes["analytics_logging"]; ok {
			log := map[string]ir.Value{}
			for _, k := range []string{"delete", "read", "write", "version"} {
				if fv, fok := objectField(v, k); fok {
					log[k] = fv
				}
			}
			if rp, rok := objectField(v, "retention_policy"); rok {
				if d, dok := objectField(rp, "days"); dok {
					log["retention_policy_days"] = d
				}
			}
			if len(log) > 0 {
				blk["logging"] = ir.Value{
					Raw:   []ir.Value{{Raw: log, Known: true, Span: v.Span}},
					Known: true, Span: v.Span,
				}
			}
		}
		if v, ok := r.Attributes["hour_metrics"]; ok {
			blk["hour_metrics"] = ir.Value{
				Raw:   []ir.Value{v},
				Known: true, Span: v.Span,
			}
		}
		if v, ok := r.Attributes["minute_metrics"]; ok {
			blk["minute_metrics"] = ir.Value{
				Raw:   []ir.Value{v},
				Known: true, Span: v.Span,
			}
		}
		if len(blk) > 0 {
			parent.Attributes["queue_properties"] = ir.Value{
				Raw:   []ir.Value{{Raw: blk, Known: true, Span: r.Span}},
				Known: true, Span: r.Span,
			}
		}
		// child dropped
	}
	return out
}

// translateStorageBlocks reshapes two storage-account property groups
// into the Terraform block forms the rule pack reads:
//
//   - properties.sasPolicy (a single object attribute) becomes a
//     sas_policy block, with sasExpirationPeriod renamed to the
//     Terraform field expiration_period.
//   - properties.encryption.keyVaultProperties becomes a
//     customer_managed_key block carrying the versioned key URL.
//
// Object-valued attributes are invisible to block-based rules, so
// without this the controls are present but unreadable — FPs
// AZURE-125 and AZURE-033 on correctly configured accounts.
func translateStorageBlocks(resources []ir.Resource) []ir.Resource {
	for i := range resources {
		r := &resources[i]
		if r.Type != "azurerm_storage_account" {
			continue
		}
		if v, ok := r.Attributes["sas_policy"]; ok {
			if obj, isObj := v.Raw.(map[string]ir.Value); isObj {
				blk := map[string]ir.Value{}
				if ep, eok := obj["sas_expiration_period"]; eok {
					blk["expiration_period"] = ep
				}
				if ea, eok := obj["expiration_action"]; eok {
					blk["expiration_action"] = ea
				}
				if len(blk) > 0 {
					r.Attributes["sas_policy"] = ir.Value{
						Raw:   []ir.Value{{Raw: blk, Known: true, Span: v.Span}},
						Known: true, Span: v.Span,
					}
				}
			}
		}
		if v, ok := r.Attributes["encryption"]; ok {
			if kv, kok := objectField(v, "key_vault_properties"); kok {
				name, nok := objectField(kv, "key_name")
				uri, uok := objectField(kv, "key_vault_uri")
				if nok && uok {
					ns, _ := name.AsString()
					us, _ := uri.AsString()
					if ns != "" && us != "" {
						keyID := strings.TrimSuffix(us, "/") + "/keys/" + ns
						if ver, vok := objectField(kv, "key_version"); vok {
							if vs, _ := ver.AsString(); vs != "" {
								keyID += "/" + vs
							}
						}
						blk := map[string]ir.Value{
							"key_vault_key_id": {Raw: keyID, Known: true, Span: kv.Span},
						}
						r.Attributes["customer_managed_key"] = ir.Value{
							Raw:   []ir.Value{{Raw: blk, Known: true, Span: kv.Span}},
							Known: true, Span: kv.Span,
						}
					}
				}
			}
		}
	}
	return resources
}

// translateVNetDNS flattens properties.dhcpOptions.dnsServers onto
// the azurerm_virtual_network resource as the flat dns_servers list
// the rule pack reads (Terraform models it as a top-level attribute).
// Without this, VNets with custom DNS configured still drew
// AZURE-058 ("without custom DNS servers").
func translateVNetDNS(resources []ir.Resource) []ir.Resource {
	for i := range resources {
		r := &resources[i]
		if r.Type != "azurerm_virtual_network" {
			continue
		}
		if _, ok := r.Attributes["dns_servers"]; ok {
			continue
		}
		if v, ok := r.Attributes["dhcp_options"]; ok {
			if ds, dok := objectField(v, "dns_servers"); dok {
				r.Attributes["dns_servers"] = ds
			}
		}
	}
	return resources
}

// snake converts camelCase to snake_case. Runs of capitals are treated as
// one word: CidrIp -> cidr_ip, DBInstanceClass -> db_instance_class.
func snake(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				prev := runes[i-1]
				nextIsLower := i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z'
				if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') ||
					((prev < 'a' || prev > 'z') && nextIsLower) {
					b.WriteByte('_')
				}
			}
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
