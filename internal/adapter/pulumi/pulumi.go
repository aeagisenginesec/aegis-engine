// Package pulumi parses Pulumi YAML programs (Pulumi.yaml) into the canonical IR.
//
// Scope: declarative Pulumi YAML only. Pulumi programs written in
// TypeScript, Python, Go, or .NET require language runtimes and are
// explicitly out of scope; see docs/PULUMI.md.
//
// A Pulumi.yaml program looks like:
//
//	name: my-project
//	runtime: yaml
//	resources:
//	  my-bucket:
//	    type: aws:s3:Bucket
//	    properties:
//	      bucket: my-bucket-name
//	      tags:
//	        env: prod
//
// Resource types are normalized to the Terraform-style canonical types
// consumed by the rule packs (aws:s3:Bucket -> aws_s3_bucket) via
// typemap.go. Property names are converted from camelCase to snake_case
// so rules written against Terraform attribute names keep working.
//
// Safety: parsing never executes anything. Pulumi intrinsic functions
// (fn::*) become explicit Unknown values. `${...}` references resolve
// against variables:/configuration:/resources: when statically known and
// become Unknown-with-Ref otherwise.
package pulumi

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"aegis/internal/ir"
)

// Adapter parses Pulumi.yaml programs into IR resources.
type Adapter struct{}

// New returns a Pulumi adapter.
func New() *Adapter { return &Adapter{} }

// Compile-time check that Adapter satisfies ir.Adapter.
var _ ir.Adapter = Adapter{}

// Name identifies the adapter. It is also reported as the per-file format
// in scan completeness.
func (Adapter) Name() string { return "pulumi" }

// Handles reports whether this adapter parses the given path: only files
// literally named Pulumi.yaml / Pulumi.yml (any case). It must be consulted
// before the manifests adapter, which claims every .yaml file.
func (Adapter) Handles(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	return base == "pulumi.yaml" || base == "pulumi.yml"
}

// Parse converts a Pulumi.yaml program into IR resources. A document without
// a resources: section yields no resources and a warning diagnostic.
func (Adapter) Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error) {
	p := &parser{path: path}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		p.diags = append(p.diags, ir.Diagnostic{
			Level:   "error",
			Message: fmt.Sprintf("pulumi: invalid YAML: %v", err),
			Span:    ir.Span{File: path},
		})
		return nil, p.diags, nil
	}
	root := nodeMap(&doc)
	if root == nil {
		p.diags = append(p.diags, ir.Diagnostic{
			Level:   "warning",
			Message: fmt.Sprintf("pulumi: %s is not a Pulumi program (no mapping at document root); skipped", path),
			Span:    ir.Span{File: path},
		})
		return nil, p.diags, nil
	}
	p.collectVars(root)
	resNode := nodeField(root, "resources")
	if resNode == nil || resNode.Kind != yaml.MappingNode {
		p.diags = append(p.diags, ir.Diagnostic{
			Level:   "warning",
			Message: fmt.Sprintf("pulumi: %s has no resources: section; nothing to scan", path),
			Span:    ir.Span{File: path},
		})
		return nil, p.diags, nil
	}
	var out []ir.Resource
	names := sortedKeys(resNode)
	for _, name := range names {
		rn := nodeField(resNode, name)
		if rn == nil || rn.Kind != yaml.MappingNode {
			p.diags = append(p.diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("pulumi: resource %q is not a mapping; skipped", name),
				Span:    p.spanOf(rn, path),
			})
			continue
		}
		out = append(out, p.resource(name, rn))
	}
	return out, p.diags, nil
}

// parser carries per-parse state.
type parser struct {
	path  string
	diags []ir.Diagnostic
	// vars holds statically-known values from variables: and configuration:
	// (defaults). Secrets and values without defaults are absent (unknown).
	vars map[string]*yaml.Node
	// resourceNames is the set of logical resource names for Ref resolution.
	resourceNames map[string]bool
}

// collectVars indexes variables: and configuration: defaults for ${...}
// reference resolution.
func (p *parser) collectVars(root *yaml.Node) {
	p.vars = map[string]*yaml.Node{}
	p.resourceNames = map[string]bool{}
	if v := nodeField(root, "variables"); v != nil && v.Kind == yaml.MappingNode {
		for _, k := range sortedKeys(v) {
			p.vars[k] = nodeField(v, k)
		}
	}
	if c := nodeField(root, "configuration"); c != nil && c.Kind == yaml.MappingNode {
		for _, k := range sortedKeys(c) {
			cn := nodeField(c, k)
			if cn == nil {
				continue
			}
			if cn.Kind == yaml.MappingNode {
				// {type:, default:, secret:} form.
				if d := nodeField(cn, "default"); d != nil {
					p.vars[k] = d
				}
				// secret without default: stays unknown (absent from vars).
			} else {
				p.vars[k] = cn
			}
		}
	}
	if r := nodeField(root, "resources"); r != nil && r.Kind == yaml.MappingNode {
		for _, k := range sortedKeys(r) {
			p.resourceNames[k] = true
		}
	}
}

// resource converts one named resource entry to an IR resource.
func (p *parser) resource(name string, rn *yaml.Node) ir.Resource {
	span := p.spanOf(rn, p.path)
	typeStr := nodeScalar(nodeField(rn, "type"))
	tfType, provider := normalizeType(typeStr)
	if typeStr != "" && !knownType(typeStr) {
		p.diags = append(p.diags, ir.Diagnostic{
			Level:   "warning",
			Message: fmt.Sprintf("pulumi: resource %q has unmapped type %q; using fallback type %q (some rules may not apply)", name, typeStr, tfType),
			Span:    span,
		})
	}
	attrs := map[string]ir.Value{}
	if props := nodeField(rn, "properties"); props != nil && props.Kind == yaml.MappingNode {
		for _, k := range sortedKeys(props) {
			attrs[toSnake(k)] = p.value(nodeField(props, k), span)
		}
	}
	// options.protect / options.ignoreChanges are metadata, not security
	// signals; they are intentionally not mapped to attributes.
	return ir.Resource{
		Type:       tfType,
		Name:       name,
		Provider:   provider,
		Attributes: attrs,
		Span:       span,
	}
}

// value converts a YAML node to an ir.Value. `${...}` strings resolve
// against variables/configuration/resources; fn::* intrinsics and anything
// unresolvable become explicit Unknown values.
func (p *parser) value(n *yaml.Node, span ir.Span) ir.Value {
	if n == nil {
		return ir.UnknownValue(span)
	}
	span = p.spanOf(n, p.path)
	switch n.Kind {
	case yaml.ScalarNode:
		return p.scalar(n, span)
	case yaml.MappingNode:
		// Single-key fn::* mapping = Pulumi intrinsic function call.
		keys := sortedKeys(n)
		if len(keys) == 1 && strings.HasPrefix(keys[0], "fn::") {
			p.diags = append(p.diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("pulumi: intrinsic %q is not statically resolvable; treated as unknown", keys[0]),
				Span:    span,
			})
			return ir.Value{Known: false, Span: span, Ref: keys[0]}
		}
		out := make(map[string]ir.Value, len(keys))
		for _, k := range keys {
			out[toSnake(k)] = p.value(nodeField(n, k), span)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case yaml.SequenceNode:
		out := make([]ir.Value, 0, len(n.Content))
		for _, e := range n.Content {
			out = append(out, p.value(e, span))
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case yaml.AliasNode:
		return p.value(n.Alias, span)
	default:
		return ir.UnknownValue(span)
	}
}

// scalar converts a YAML scalar node. Strings of the form ${name} or
// ${name.attr} are references; everything else is a known scalar.
func (p *parser) scalar(n *yaml.Node, span ir.Span) ir.Value {
	switch n.Tag {
	case "!!null":
		return ir.UnknownValue(span)
	case "!!bool":
		return ir.Value{Raw: n.Value == "true", Known: true, Span: span}
	case "!!int":
		var i int64
		fmt.Sscanf(n.Value, "%d", &i)
		return ir.Value{Raw: float64(i), Known: true, Span: span}
	case "!!float":
		var f float64
		fmt.Sscanf(n.Value, "%g", &f)
		return ir.Value{Raw: f, Known: true, Span: span}
	default:
		s := n.Value
		if ref, ok := parseRef(s); ok {
			return p.resolveRef(ref, span)
		}
		return ir.Value{Raw: s, Known: true, Span: span}
	}
}

// parseRef reports whether s is a ${...} reference and returns its body.
func parseRef(s string) (string, bool) {
	if len(s) > 3 && strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
		return s[2 : len(s)-1], true
	}
	return "", false
}

// resolveRef resolves a ${name} or ${name.attr.path} reference against
// variables, configuration defaults, and resource names.
func (p *parser) resolveRef(ref string, span ir.Span) ir.Value {
	head := ref
	if i := strings.Index(head, "."); i >= 0 {
		head = head[:i]
	}
	if v, ok := p.vars[head]; ok {
		// Statically-known variable/config value: inline it.
		return p.value(v, span)
	}
	if p.resourceNames[head] {
		return ir.Value{Known: false, Span: span, Ref: ref}
	}
	// Unknown name: explicit unknown with the ref recorded.
	return ir.Value{Known: false, Span: span, Ref: ref}
}

// spanOf builds an ir.Span from a YAML node's line info.
func (p *parser) spanOf(n *yaml.Node, path string) ir.Span {
	if n == nil {
		return ir.Span{File: path, StartLine: 1, StartCol: 1}
	}
	return ir.Span{File: path, StartLine: n.Line, StartCol: n.Column}
}

// nodeMap returns the document's root mapping node, unwrapping the
// top-level DocumentNode.
func nodeMap(doc *yaml.Node) *yaml.Node {
	n := doc
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind == yaml.MappingNode {
		return n
	}
	return nil
}

// nodeField returns the value node for key k in mapping m, or nil.
func nodeField(m *yaml.Node, k string) *yaml.Node {
	n := m
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == k {
			return n.Content[i+1]
		}
	}
	return nil
}

// sortedKeys returns the mapping's keys in sorted order for determinism.
func sortedKeys(m *yaml.Node) []string {
	n := m
	keys := make([]string, 0, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		keys = append(keys, n.Content[i].Value)
	}
	sort.Strings(keys)
	return keys
}

// nodeScalar returns the scalar string value of n, or "".
func nodeScalar(n *yaml.Node) string {
	if n != nil && n.Kind == yaml.ScalarNode {
		return n.Value
	}
	return ""
}

// toSnake converts camelCase (and SCREAMING keys) to snake_case.
// Already-snake names pass through unchanged.
func toSnake(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 4)
	runes := []rune(s)
	for i, r := range runes {
		if !unicode.IsUpper(r) {
			b.WriteRune(r)
			continue
		}
		if i > 0 {
			prev := runes[i-1]
			lowerPrev := unicode.IsLower(prev) || unicode.IsDigit(prev)
			lowerNext := i+1 < len(runes) && unicode.IsLower(runes[i+1])
			// Split before an uppercase that starts a new word: either it
			// follows a lowercase/digit (serverSide) or it is the last
			// uppercase before a lowercase run (HTTPServer -> http_server).
			if lowerPrev || lowerNext {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}
