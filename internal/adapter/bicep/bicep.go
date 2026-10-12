// Package bicep implements ir.Adapter for Bicep files.
//
// Strategy: Bicep compiles to ARM. Rather than shelling out to the bicep
// CLI (not guaranteed present), this adapter implements a lightweight
// parser for the common Bicep subset and translates it into ARM-equivalent
// structures, then reuses the arm package's resource builder. All 313
// Azure rules apply automatically with zero new rules.
//
// Supported subset:
//   - param <name> <type> = <default>
//   - var <name> = <expr>
//   - resource <sym> '<type>@<apiVersion>' = { ... }
//   - resource <sym> '<type>@<apiVersion>' existing = { ... } (skipped: not managed)
//   - targetScope, output, module, import: skipped with diagnostics
//   - Values: strings (with ${} interpolation), numbers, bools, arrays,
//     objects, identifiers, function calls, property/index access, ternary.
//
// Non-static expressions are translated to ARM [...] expression strings
// (e.g. '${a}-x' -> [concat(variables('a'), '-x')]) so the arm package's
// evaluator resolves what it can and marks the rest Unknown.
package bicep

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"aegis/internal/adapter/arm"
	"aegis/internal/ir"
)

// Adapter parses Bicep files into the canonical IR.
type Adapter struct{}

// Compile-time check that Adapter satisfies ir.Adapter.
var _ ir.Adapter = Adapter{}

// New constructs the adapter.
func New() *Adapter { return &Adapter{} }

// Name identifies the adapter.
func (Adapter) Name() string { return "bicep" }

// Handles reports whether the path is a Bicep file.
func (Adapter) Handles(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".bicep")
}

// Parse converts Bicep source into IR resources via ARM translation.
func (Adapter) Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error) {
	p := &parser{path: path, src: string(src)}
	tmpl, diags := p.parse()
	if tmpl == nil {
		return nil, diags, nil
	}
	resources, rdiags := arm.BuildResources(path, tmpl)
	return resources, append(diags, rdiags...), nil
}

// parser holds per-parse state.
type parser struct {
	path  string
	src   string
	pos   int
	diags []ir.Diagnostic
	// declared identifiers
	params  map[string]bool
	vars    map[string]bool
	resSym  map[string]string // resource symbol -> ARM type
	resName map[string]tval   // resource symbol -> translated name
}

func (p *parser) diag(level, msg string) {
	p.diags = append(p.diags, ir.Diagnostic{
		Level:   level,
		Message: fmt.Sprintf("bicep: %s", msg),
		Span:    ir.Span{File: p.path, StartLine: 1, StartCol: 1},
	})
}

// tval is a translated value: either a static Go value or an ARM
// expression string (isExpr=true) for the arm evaluator.
type tval struct {
	v      any
	isExpr bool
}

func static(v any) tval  { return tval{v: v} }
func expr(s string) tval { return tval{v: s, isExpr: true} }

// unknownExpr is an ARM expression guaranteed to evaluate Unknown.
func unknownExpr() tval { return expr("[unknown()]") }

// parse is the top-level driver: returns an ARM-template-equivalent map.
func (p *parser) parse() (map[string]any, []ir.Diagnostic) {
	p.params = map[string]bool{}
	p.vars = map[string]bool{}
	p.resSym = map[string]string{}
	p.resName = map[string]tval{}
	tmpl := map[string]any{
		"$schema":        "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		"contentVersion": "1.0.0.0",
		"parameters":     map[string]any{},
		"variables":      map[string]any{},
		"resources":      []any{},
	}
	params := tmpl["parameters"].(map[string]any)
	variables := tmpl["variables"].(map[string]any)
	var resources []any

	for {
		p.skipWSAndComments()
		if p.pos >= len(p.src) {
			break
		}
		// decorators: @name or @name(...)
		for p.peek() == '@' {
			p.skipDecorator()
			p.skipWSAndComments()
		}
		kw := p.parseKeyword()
		switch kw {
		case "param":
			name, ptype, def := p.parseParam()
			if name == "" {
				break
			}
			p.params[name] = true
			entry := map[string]any{"type": ptype}
			if def != nil {
				entry["defaultValue"] = def.v
			}
			params[name] = entry
		case "var":
			name, val := p.parseVar()
			if name == "" {
				break
			}
			p.vars[name] = true
			variables[name] = val.v
		case "resource":
			rmap := p.parseResource()
			if rmap != nil {
				resources = append(resources, rmap)
			}
		case "module", "output", "import", "using", "targetScope", "func", "type":
			p.diag("warning", fmt.Sprintf("statement %q is not supported; skipped", kw))
			p.skipStatement()
		default:
			if kw == "" {
				// Unparseable: skip one char to avoid infinite loop.
				p.pos++
			} else {
				p.diag("warning", fmt.Sprintf("unexpected token %q; skipped", kw))
				p.skipStatement()
			}
		}
	}
	tmpl["resources"] = resources
	return tmpl, p.diags
}

// --- lexer helpers ---

func (p *parser) peek() byte {
	if p.pos >= len(p.src) {
		return 0
	}
	return p.src[p.pos]
}

func (p *parser) skipWSAndComments() {
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			p.pos++
			continue
		}
		if ch == '/' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '/' {
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
			continue
		}
		break
	}
}

func isIdentStart(ch byte) bool {
	return ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}
func isIdentChar(ch byte) bool { return isIdentStart(ch) || (ch >= '0' && ch <= '9') }

func (p *parser) parseKeyword() string {
	p.skipWSAndComments()
	start := p.pos
	for p.pos < len(p.src) && isIdentChar(p.src[p.pos]) {
		p.pos++
	}
	return p.src[start:p.pos]
}

func (p *parser) parseIdent() string {
	start := p.pos
	if p.pos < len(p.src) && isIdentStart(p.src[p.pos]) {
		p.pos++
		for p.pos < len(p.src) && isIdentChar(p.src[p.pos]) {
			p.pos++
		}
	}
	return p.src[start:p.pos]
}

func (p *parser) expect(ch byte) bool {
	p.skipWSAndComments()
	if p.peek() == ch {
		p.pos++
		return true
	}
	return false
}

// skipDecorator consumes @name or @name(...).
func (p *parser) skipDecorator() {
	p.pos++ // @
	p.parseIdent()
	p.skipWSAndComments()
	if p.peek() == '(' {
		depth := 0
		for p.pos < len(p.src) {
			ch := p.src[p.pos]
			if ch == '\'' {
				p.skipBicepString()
				continue
			}
			if ch == '(' {
				depth++
			} else if ch == ')' {
				depth--
				if depth == 0 {
					p.pos++
					break
				}
			}
			p.pos++
		}
	}
}

// skipBicepString consumes a '...' or ”'...”' string.
func (p *parser) skipBicepString() {
	if strings.HasPrefix(p.src[p.pos:], "'''") {
		p.pos += 3
		for p.pos < len(p.src) && !strings.HasPrefix(p.src[p.pos:], "'''") {
			p.pos++
		}
		p.pos += 3
		return
	}
	p.pos++ // '
	for p.pos < len(p.src) {
		if p.src[p.pos] == '\'' {
			p.pos++
			return
		}
		if p.src[p.pos] == '\\' && p.pos+1 < len(p.src) {
			p.pos += 2
			continue
		}
		p.pos++
	}
}

// skipStatement skips to the end of the current line or balanced brace.
func (p *parser) skipStatement() {
	p.skipWSAndComments()
	depth := 0
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == '\'' {
			p.skipBicepString()
			continue
		}
		if ch == '/' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '/' {
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
			if depth == 0 {
				return
			}
			continue
		}
		switch ch {
		case '{', '[', '(':
			depth++
		case '}', ']', ')':
			if depth == 0 {
				return
			}
			depth--
		case '\n':
			if depth == 0 {
				p.pos++
				return
			}
		}
		p.pos++
	}
}

// --- top-level statements ---

// parseParam parses: param <name> <type> = <default>
func (p *parser) parseParam() (string, string, *tval) {
	p.skipWSAndComments()
	name := p.parseIdent()
	if name == "" {
		return "", "", nil
	}
	p.skipWSAndComments()
	ptype := p.parseIdent() // string, int, bool, array, object, secureString...
	var def *tval
	p.skipWSAndComments()
	if p.peek() == '=' {
		p.pos++
		v := p.parseExpr()
		def = &v
	}
	if ptype == "" {
		ptype = "string"
	}
	return name, ptype, def
}

// parseVar parses: var <name> = <expr>
func (p *parser) parseVar() (string, tval) {
	p.skipWSAndComments()
	name := p.parseIdent()
	if name == "" {
		return "", static(nil)
	}
	if !p.expect('=') {
		p.diag("warning", fmt.Sprintf("var %q missing =", name))
		return "", static(nil)
	}
	return name, p.parseExpr()
}

// parseResource parses: resource <sym> '<type>@<api>' [=|existing =] { ... }
// or the for-loop form (skipped with warning).
func (p *parser) parseResource() map[string]any {
	p.skipWSAndComments()
	sym := p.parseIdent()
	if sym == "" {
		return nil
	}
	p.skipWSAndComments()
	typeStr := p.parseTypeString()
	if typeStr == "" {
		p.diag("warning", fmt.Sprintf("resource %q missing type string", sym))
		p.skipStatement()
		return nil
	}
	armType := typeStr
	if idx := strings.Index(armType, "@"); idx >= 0 {
		armType = armType[:idx]
	}
	p.skipWSAndComments()
	// Peek for the "existing" keyword without consuming other tokens.
	existing := false
	saved := p.pos
	kw := p.parseKeyword()
	if kw == "existing" {
		existing = true
	} else {
		p.pos = saved // not "existing": rewind, expect '=' next
	}
	p.skipWSAndComments()
	if !p.expect('=') {
		p.diag("warning", fmt.Sprintf("resource %q missing =", sym))
		return nil
	}
	p.skipWSAndComments()
	// for-loop form: = [for ...]
	if p.peek() == '[' {
		p.diag("warning", fmt.Sprintf("resource %q uses a for-loop; not expanded, skipped", sym))
		p.skipStatement()
		return nil
	}
	if !p.expect('{') {
		p.diag("warning", fmt.Sprintf("resource %q body is not an object", sym))
		return nil
	}
	body := p.parseObject()
	if existing {
		p.diag("warning", fmt.Sprintf("resource %q is 'existing' (not managed); skipped", sym))
		return nil
	}
	p.resSym[sym] = armType
	rmap := map[string]any{"type": armType}
	// name (required in ARM-ish form)
	if nv, ok := body["name"]; ok {
		rmap["name"] = nv
	} else {
		rmap["name"] = sym
	}
	// Record the translated name for parent: resolution by child resources.
	if ns, ok := rmap["name"].(string); ok && !isARMExpr(ns) {
		p.resName[sym] = static(ns)
	} else {
		p.resName[sym] = tval{v: rmap["name"]}
	}
	for _, k := range []string{"location", "kind", "sku", "tags", "properties", "identity", "zones", "dependsOn", "plan", "extendedLocation"} {
		if v, ok := body[k]; ok {
			rmap[k] = v
		}
	}
	// parent: child resource naming parent/child
	if pv, ok := body["parent"]; ok {
		rmap["name"] = joinParentChild(pv, rmap["name"])
		delete(body, "parent")
	}
	// Copy any other top-level keys through.
	for k, v := range body {
		if _, ok := rmap[k]; !ok {
			rmap[k] = v
		}
	}
	return rmap
}

// joinParentChild builds "parent/child" from translated values.
func joinParentChild(parent, child any) any {
	ps, pok := parent.(string)
	cs, cok := child.(string)
	if pok && cok && !isARMExpr(ps) && !isARMExpr(cs) {
		return ps + "/" + cs
	}
	return "[" + "concat(" + toFrag(parent) + ", '/', " + toFrag(child) + ")" + "]"
}

func isARMExpr(s string) bool {
	return len(s) >= 2 && s[0] == '[' && s[1] != '[' && strings.HasSuffix(strings.TrimSpace(s), "]")
}

// parseTypeString parses the '<type>@<apiVersion>' string.
func (p *parser) parseTypeString() string {
	p.skipWSAndComments()
	if p.peek() != '\'' {
		return ""
	}
	s, ok := p.parseBicepString()
	if !ok {
		return ""
	}
	if sv, ok := s.(string); ok {
		return sv
	}
	return ""
}

// --- expression parsing ---

// parseExpr parses a Bicep value expression.
func (p *parser) parseExpr() tval {
	v, ok := p.parseTernary()
	if !ok {
		return unknownExpr()
	}
	return v
}

func (p *parser) parseTernary() (tval, bool) {
	cond, ok := p.parsePrimary()
	if !ok {
		return tval{}, false
	}
	p.skipWSAndComments()
	if p.peek() == '?' {
		p.pos++
		a := p.parseExpr()
		p.skipWSAndComments()
		if !p.expect(':') {
			return tval{}, false
		}
		b := p.parseExpr()
		return expr("[if(" + toFrag(cond.v) + ", " + toFrag(a.v) + ", " + toFrag(b.v) + ")]"), true
	}
	return cond, true
}

// parsePrimary parses strings, numbers, bools, arrays, objects,
// identifiers (with suffixes), and function calls.
func (p *parser) parsePrimary() (tval, bool) {
	p.skipWSAndComments()
	if p.pos >= len(p.src) {
		return tval{}, false
	}
	ch := p.src[p.pos]
	switch {
	case ch == '\'':
		return p.parseStringVal()
	case ch == '[':
		return p.parseArray()
	case ch == '{':
		p.pos++
		return p.parseObjectVal()
	case ch == '-' || (ch >= '0' && ch <= '9'):
		n, ok := p.parseNumber()
		if !ok {
			return tval{}, false
		}
		return static(n), true
	case isIdentStart(ch):
		return p.parseIdentOrCall()
	}
	return tval{}, false
}

// parseStringVal parses '...' or ”'...”' with ${} interpolation.
func (p *parser) parseStringVal() (tval, bool) {
	multiline := strings.HasPrefix(p.src[p.pos:], "'''")
	var raw string
	if multiline {
		p.pos += 3
		start := p.pos
		for p.pos < len(p.src) && !strings.HasPrefix(p.src[p.pos:], "'''") {
			p.pos++
		}
		raw = p.src[start:p.pos]
		p.pos += 3
	} else {
		p.pos++ // '
		var b strings.Builder
		for p.pos < len(p.src) {
			ch := p.src[p.pos]
			if ch == '\'' {
				if p.pos+1 < len(p.src) && p.src[p.pos+1] == '\'' {
					b.WriteByte('\'')
					p.pos += 2
					continue
				}
				p.pos++
				break
			}
			if ch == '\\' && p.pos+1 < len(p.src) {
				b.WriteByte(p.src[p.pos+1])
				p.pos += 2
				continue
			}
			b.WriteByte(ch)
			p.pos++
		}
		raw = b.String()
	}
	return p.interpolate(raw), true
}

// interpolate converts ${...} segments to an ARM concat expression.
// No interpolation -> static string.
func (p *parser) interpolate(s string) tval {
	if !strings.Contains(s, "${") {
		return static(s)
	}
	var parts []string
	i := 0
	for i < len(s) {
		j := strings.Index(s[i:], "${")
		if j < 0 {
			if i < len(s) {
				parts = append(parts, armQuote(s[i:]))
			}
			break
		}
		if j > 0 {
			parts = append(parts, armQuote(s[i:i+j]))
		}
		i += j + 2
		depth := 1
		start := i
		for i < len(s) && depth > 0 {
			if s[i] == '{' {
				depth++
			} else if s[i] == '}' {
				depth--
			} else if s[i] == '\'' {
				// skip string
				i++
				for i < len(s) && s[i] != '\'' {
					i++
				}
			}
			i++
		}
		inner := s[start : i-1]
		parts = append(parts, p.bicepInnerToARM(inner))
	}
	if len(parts) == 1 && !strings.HasPrefix(parts[0], "'") {
		return expr("[" + parts[0] + "]")
	}
	return expr("[concat(" + strings.Join(parts, ", ") + ")]")
}

// bicepInnerToARM translates the inside of ${...} to an ARM fragment.
// Handles dotted paths and simple calls on identifiers.
func (p *parser) bicepInnerToARM(inner string) string {
	inner = strings.TrimSpace(inner)
	// Find the root identifier.
	i := 0
	for i < len(inner) && (isIdentChar(inner[i])) {
		i++
	}
	root := inner[:i]
	rest := inner[i:]
	frag := p.identFrag(root)
	if frag == "" || frag == "unknown()" {
		return "unknown()"
	}
	return frag + rest
}

// parseBicepString parses a string and returns its raw content.
func (p *parser) parseBicepString() (any, bool) {
	v, ok := p.parseStringVal()
	if !ok {
		return nil, false
	}
	return v.v, true
}

func (p *parser) parseNumber() (float64, bool) {
	start := p.pos
	if p.src[p.pos] == '-' {
		p.pos++
	}
	for p.pos < len(p.src) && ((p.src[p.pos] >= '0' && p.src[p.pos] <= '9') || p.src[p.pos] == '.') {
		p.pos++
	}
	f, err := strconv.ParseFloat(p.src[start:p.pos], 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// parseArray parses [...] with comma- or newline-separated elements.
func (p *parser) parseArray() (tval, bool) {
	p.pos++ // [
	var out []any
	for {
		p.skipWSAndComments()
		if p.pos >= len(p.src) {
			return tval{}, false
		}
		if p.src[p.pos] == ']' {
			p.pos++
			break
		}
		v := p.parseExpr()
		out = append(out, v.v)
		p.skipWSAndComments()
		if p.peek() == ',' {
			p.pos++
		}
	}
	if out == nil {
		out = []any{}
	}
	return static(out), true
}

// parseObject parses { key: value, ... } and returns the map.
func (p *parser) parseObject() map[string]any {
	out := map[string]any{}
	for {
		p.skipWSAndComments()
		if p.pos >= len(p.src) || p.src[p.pos] == '}' {
			if p.pos < len(p.src) {
				p.pos++
			}
			break
		}
		var key string
		if p.src[p.pos] == '\'' {
			kv, ok := p.parseBicepString()
			if !ok {
				break
			}
			key, _ = kv.(string)
		} else {
			key = p.parseIdent()
		}
		if key == "" {
			break
		}
		if !p.expect(':') {
			break
		}
		v := p.parseExpr()
		out[key] = v.v
		p.skipWSAndComments()
		if p.peek() == ',' {
			p.pos++
		}
	}
	return out
}

// parseObjectVal wraps parseObject as a tval.
func (p *parser) parseObjectVal() (tval, bool) {
	return static(p.parseObject()), true
}

// parseIdentOrCall parses identifiers with .prop/[n] suffixes, function
// calls, and the true/false/null literals.
func (p *parser) parseIdentOrCall() (tval, bool) {
	name := p.parseIdent()
	switch name {
	case "true":
		return static(true), true
	case "false":
		return static(false), true
	case "null":
		return static(nil), true
	}
	p.skipWSAndComments()
	if p.peek() == '(' {
		return p.parseCall(name)
	}
	frag := p.identFrag(name)
	// suffixes: .prop, [n], ['k']
	for {
		p.skipWSAndComments()
		if p.peek() == '.' {
			p.pos++
			prop := p.parseIdent()
			if prop == "" {
				return tval{}, false
			}
			frag += "." + prop
		} else if p.peek() == '[' {
			p.pos++
			p.skipWSAndComments()
			if p.peek() == '\'' {
				kv, ok := p.parseBicepString()
				if !ok {
					return tval{}, false
				}
				ks, _ := kv.(string)
				frag += "[" + armQuote(ks) + "]"
				p.skipWSAndComments()
				if !p.expect(']') {
					return tval{}, false
				}
			} else {
				n, ok := p.parseNumber()
				if !ok {
					return tval{}, false
				}
				if !p.expect(']') {
					return tval{}, false
				}
				frag += "[" + strconv.FormatFloat(n, 'f', -1, 64) + "]"
			}
		} else {
			break
		}
	}
	if frag == "" {
		return unknownExpr(), true
	}
	return expr("[" + frag + "]"), true
}

// identFrag maps a bare identifier to an ARM fragment (no brackets).
func (p *parser) identFrag(name string) string {
	switch {
	case p.params[name]:
		return "parameters('" + name + "')"
	case p.vars[name]:
		return "variables('" + name + "')"
	case p.resSym[name] != "":
		// Resource symbol: resolve to its name when statically known so
		// parent: references produce readable child names.
		if nv, ok := p.resName[name]; ok {
			return toFrag(nv.v)
		}
		return "unknown()"
	default:
		return "unknown()"
	}
}

// parseCall parses f(arg, ...) and translates to an ARM expression.
func (p *parser) parseCall(name string) (tval, bool) {
	// Special namespace-ish identifiers.
	lower := strings.ToLower(name)
	p.pos++ // (
	var args []string
	p.skipWSAndComments()
	if p.peek() != ')' {
		for {
			a := p.parseExpr()
			args = append(args, toFrag(a.v))
			p.skipWSAndComments()
			if p.peek() == ',' {
				p.pos++
				continue
			}
			break
		}
	}
	if !p.expect(')') {
		return tval{}, false
	}
	_ = lower
	return expr("[" + name + "(" + strings.Join(args, ", ") + ")]"), true
}

// toFrag renders a translated value as an ARM expression fragment.
func toFrag(v any) string {
	if s, ok := v.(string); ok && isARMExpr(s) {
		inner := strings.TrimSpace(s[1 : len(s)-1])
		return inner
	}
	return armLit(v)
}

// armLit renders a static Go value as an ARM literal.
func armLit(v any) string {
	switch tv := v.(type) {
	case nil:
		return "null"
	case string:
		return armQuote(tv)
	case bool:
		return strconv.FormatBool(tv)
	case float64:
		return strconv.FormatFloat(tv, 'f', -1, 64)
	case []any:
		parts := make([]string, 0, len(tv))
		for _, e := range tv {
			parts = append(parts, toFrag(e))
		}
		return "createArray(" + strings.Join(parts, ", ") + ")"
	case map[string]any:
		// Objects can't be ARM literals; mark unknown.
		return "unknown()"
	default:
		return "unknown()"
	}
}

// armQuote quotes a string for ARM expressions (” escapes quotes).
func armQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
