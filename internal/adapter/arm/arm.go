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
	return looksLikeARM(path)
}

// looksLikeARM reads the file (bounded) and checks for the ARM deployment
// template schema marker.
func looksLikeARM(path string) bool {
	src, err := readBounded(path, 64<<10) // 64 KiB is plenty for a $schema scan
	if err != nil {
		return false
	}
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
}

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
func (c *evalCtx) evalExpression(s string) ir.Value {
	span := c.t.span
	if lit, ok := unescapeBracket(s); ok {
		return ir.Value{Raw: lit, Known: true, Span: span}
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	v, ok := c.parseExpr(inner)
	if !ok {
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
		if !v.Known {
			// Once unknown, remaining suffixes keep it unknown.
			// Still need to consume them for parse validity.
		}
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
		if c.varStack[n] {
			return unknown // cycle
		}
		raw, ok := c.t.variables[n]
		if !ok {
			return unknown
		}
		c.varStack[n] = true
		v := c.eval(raw)
		delete(c.varStack, n)
		return v
	case "concat":
		var b strings.Builder
		for _, a := range args {
			s, ok := a.AsString()
			if !ok {
				return unknown
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
		for _, e := range l {
			s, ok := e.AsString()
			if !ok {
				return unknown
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
	}
	// Everything else (resourceId, reference, listKeys, subscription(),
	// resourceGroup(), if(), equals(), guid(), uniqueString(), utcNow(),
	// providers(), extensionResourceId(), ...) -> explicit Unknown.
	return unknown
}

// mapResource converts one ARM resource's fields into IR attributes:
// top-level fields (location, tags, kind, sku, identity) plus the
// properties object flattened with per-type renames.
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
	for k, v := range props {
		name := k
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
	// Convert ARM publicNetworkAccess enum to boolean for mssql servers.
	// ARM uses "Enabled"/"Disabled", TF rules expect a boolean.
	if res.Type == "azurerm_mssql_server" {
		if v, ok := res.Attributes["public_network_access_enabled"]; ok {
			if s, ok := v.AsString(); ok {
				switch s {
				case "Enabled":
					res.Attributes["public_network_access_enabled"] = ir.Value{Raw: true, Known: true, Span: v.Span}
				case "Disabled":
					res.Attributes["public_network_access_enabled"] = ir.Value{Raw: false, Known: true, Span: v.Span}
				}
			}
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
									name := pk
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
	_ = span
}

// foldBlobServices merges Microsoft.Storage/storageAccounts/blobServices
// child resources into their parent storage account as a blob_properties
// block, so the blob-property rules apply. The child resource itself is
// dropped (it carries no independent security surface).
func foldBlobServices(resources []ir.Resource, t *template) []ir.Resource {
	byAddr := map[string]int{}
	for i, r := range resources {
		byAddr[r.Type+"\x00"+r.Name] = i
	}
	var out []ir.Resource
	for _, r := range resources {
		if r.Type != "arm_Microsoft.Storage/storageAccounts/blobServices" &&
			r.Type != "azurerm_storage_account_blob_services" {
			out = append(out, r)
			continue
		}
		// Child name is "<account>/default": find the parent account.
		parentName := r.Name
		if idx := strings.Index(parentName, "/"); idx >= 0 {
			parentName = parentName[:idx]
		}
		pi, ok := byAddr["azurerm_storage_account\x00"+parentName]
		if !ok {
			out = append(out, r) // orphan: keep as-is
			continue
		}
		parent := &out[pi]
		blk := map[string]ir.Value{}
		if v, ok := r.Attributes["is_versioning_enabled"]; ok {
			blk["versioning_enabled"] = v
		}
		if v, ok := r.Attributes["delete_retention_policy"]; ok {
			blk["delete_retention_policy"] = v
		}
		if v, ok := r.Attributes["change_feed_enabled"]; ok {
			blk["change_feed_enabled"] = v
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
					(!(prev >= 'a' && prev <= 'z') && nextIsLower) {
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
