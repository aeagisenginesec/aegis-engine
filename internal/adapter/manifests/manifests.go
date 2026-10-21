// Package manifests parses Kubernetes YAML manifests and CloudFormation
// templates (YAML or JSON) into the canonical IR.
//
// Scope (Milestone 5):
//   - .yaml/.yml: multi-document YAML; .json: single document (except
//     .plan.json, which belongs to the planjson adapter).
//   - Kubernetes: documents with string apiVersion+kind become k8s_<Kind>
//     resources carrying the whole document as attributes.
//   - CloudFormation: templates become normalized AWS resources so the
//     existing AWS rule pack applies (e.g. AWS::S3::Bucket ->
//     aws_s3_bucket). See cfn.go for the normalization table.
//
// Safety: parsing never executes anything. CloudFormation intrinsics other
// than Ref and Fn::GetAtt become explicit Unknown values. Multi-document
// bombs are bounded by the discovery layer's file-size caps (documented
// here, enforced there).
package manifests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"aegis/internal/ir"
)

// Adapter parses manifest files (.yaml/.yml/.json) into IR resources.
type Adapter struct{}

// Compile-time check that Adapter satisfies ir.Adapter.
var _ ir.Adapter = Adapter{}

// Name identifies the adapter.
func (Adapter) Name() string { return "manifests" }

// Handles reports whether this adapter parses the given path.
// .plan.json is explicitly excluded: it belongs to the planjson adapter,
// which the CLI consults first. The exclusion is defensive.
func (Adapter) Handles(path string) bool {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".plan.json") {
		return false
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".json":
		return true
	}
	return false
}

// Parse converts manifest source into IR resources. Malformed documents
// become error diagnostics; content problems never produce a hard error.
func (Adapter) Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error) {
	p := &parser{path: path}
	var out []ir.Resource
	for i, doc := range p.decode(src) {
		out = append(out, p.parseDocument(doc.value, i, doc.line)...)
	}
	return out, p.diags, nil
}

// decodedDoc is one decoded document plus the 1-based source line of
// its root node, so resource spans can point at the document's real
// position in the file.
type decodedDoc struct {
	value any
	line  int
}

// parser carries per-parse state: the path and accumulated diagnostics.
type parser struct {
	path       string
	diags      []ir.Diagnostic
	warnedKeys bool // non-string map key warning emitted once per file
}

// decode splits source into documents: multi-document YAML for
// .yaml/.yml, a single JSON document for .json. Decode failures become
// error diagnostics and stop the parse.
//
// YAML is decoded to yaml.Node first, then converted to plain Go values
// by nodeConverter — never via Decode(&doc any). Decoding a whole
// document into `any` makes yaml.v3 collect one error per duplicate
// mapping key, and that check is quadratic: a 12 KiB file with 2000
// duplicate keys produced a 113 MB error string, and a 30 KiB file
// OOM-killed the process (Item 5, 2026-10-13). The Node path does no
// duplicate-key checking at all; the converter below fails fast on the
// first duplicate with a single short diagnostic.
func (p *parser) decode(src []byte) []decodedDoc {
	if strings.HasSuffix(strings.ToLower(p.path), ".json") {
		var doc any
		if err := json.Unmarshal(src, &doc); err != nil {
			p.diags = append(p.diags, ir.Diagnostic{
				Level:   "error",
				Message: fmt.Sprintf("manifests: invalid JSON: %v", err),
				Span:    ir.Span{File: p.path},
			})
			return nil
		}
		if doc == nil {
			return nil
		}
		return []decodedDoc{{value: doc, line: 1}}
	}
	var docs []decodedDoc
	dec := yaml.NewDecoder(bytes.NewReader(src))
	for {
		var node yaml.Node
		if err := dec.Decode(&node); err != nil {
			if err == io.EOF {
				break
			}
			p.diags = append(p.diags, ir.Diagnostic{
				Level:   "error",
				Message: fmt.Sprintf("manifests: invalid YAML: %v", err),
				Span:    ir.Span{File: p.path},
			})
			// Keep documents decoded before the failure: discarding
			// them silently drops their findings (a valid Pod before a
			// malformed document would vanish with only this error
			// diagnostic to show for it). Only the failing document
			// itself is lost, and the error diagnostic says so.
			return docs
		}
		if len(node.Content) == 0 {
			continue // empty document (bare --- separator)
		}
		cv := &nodeConverter{inProgress: map[*yaml.Node]bool{}}
		doc, err := cv.convert(node.Content[0])
		if err != nil {
			p.diags = append(p.diags, ir.Diagnostic{
				Level:   "error",
				Message: fmt.Sprintf("manifests: invalid YAML: %v", err),
				Span:    ir.Span{File: p.path},
			})
			return docs
		}
		if doc == nil {
			continue
		}
		line := node.Content[0].Line
		if line <= 0 {
			line = 1
		}
		docs = append(docs, decodedDoc{value: doc, line: line})
	}
	return docs
}

// nodeConverter converts a yaml.Node tree to the plain Go values the
// rest of the adapter expects (map[string]any / map[any]any / []any /
// scalars / nil), mirroring what yaml.v3's Decode(&doc any) used to
// produce, with three safety properties the library path lacked:
//
//   - Duplicate mapping keys fail fast with one short error instead of
//     a quadratic error list.
//   - Alias expansion is bounded by maxConvertedNodes: "billion laughs"
//     DAGs (each level doubling the previous) abort with a clear error
//     instead of expanding exponentially. Aliases are deliberately NOT
//     shared by reference: the converted tree is fully materialized, so
//     no downstream code can alias-mutate a sibling's slice/map.
//   - An alias to an ancestor (cyclic anchor) is an error, not infinite
//     recursion.
//
// Merge keys (`<<`) are honored: explicit keys win over merged keys,
// and earlier merge sources win over later ones.
type nodeConverter struct {
	nodes      int
	inProgress map[*yaml.Node]bool
}

// maxConvertedNodes caps the materialized YAML tree per document. A
// 10 MiB source file cannot hold a legitimate tree anywhere near this
// large without alias expansion (which is exactly what the cap stops).
const maxConvertedNodes = 2000000

func (c *nodeConverter) convert(n *yaml.Node) (any, error) {
	if n == nil {
		return nil, nil
	}
	c.nodes++
	if c.nodes > maxConvertedNodes {
		return nil, fmt.Errorf("YAML node budget exceeded (%d nodes); refusing to expand aliases further", maxConvertedNodes)
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return c.convert(n.Content[0])
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, nil
		}
		if c.inProgress[n.Alias] {
			return nil, fmt.Errorf("cyclic YAML alias (anchor %q)", n.Value)
		}
		// Expand (do not share): the budget above bounds the work.
		return c.convert(n.Alias)
	case yaml.ScalarNode:
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	case yaml.SequenceNode:
		c.inProgress[n] = true
		defer delete(c.inProgress, n)
		out := make([]any, 0, len(n.Content))
		for _, e := range n.Content {
			v, err := c.convert(e)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		return c.convertMapping(n)
	default:
		return nil, fmt.Errorf("unsupported YAML node kind %d", n.Kind)
	}
}

// keyFingerprint identifies a mapping key for duplicate/merge comparison
// without assuming the key is hashable or comparable.
func keyFingerprint(k any) string { return fmt.Sprintf("%T:%#v", k, k) }

func (c *nodeConverter) convertMapping(n *yaml.Node) (any, error) {
	c.inProgress[n] = true
	defer delete(c.inProgress, n)
	type kv struct {
		k any
		v any
	}
	var pairs []kv
	seen := map[string]bool{}
	var merges []*yaml.Node
	allStrings := true
	for i := 0; i+1 < len(n.Content); i += 2 {
		kn, vn := n.Content[i], n.Content[i+1]
		// Only the !!merge tag is a merge key: a quoted "<<" is a
		// literal key, not a merge.
		if kn.Tag == "!!merge" {
			merges = append(merges, vn)
			continue
		}
		k, err := c.convert(kn)
		if err != nil {
			return nil, err
		}
		fp := keyFingerprint(k)
		if seen[fp] {
			return nil, fmt.Errorf("mapping key %q already defined at line %d", kn.Value, kn.Line)
		}
		seen[fp] = true
		if _, ok := k.(string); !ok {
			allStrings = false
		}
		v, err := c.convert(vn)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, kv{k, v})
	}
	// Apply merge sources: explicit keys win; earlier sources win.
	for _, m := range merges {
		for _, src := range c.mergeSources(m) {
			sv, err := c.convert(src)
			if err != nil {
				return nil, err
			}
			sm, ok := toStringOrAnyMap(sv)
			if !ok {
				return nil, fmt.Errorf("merge key << requires a mapping")
			}
			for k, v := range sm {
				if _, ok := k.(string); !ok {
					allStrings = false
				}
				if fp := keyFingerprint(k); !seen[fp] {
					seen[fp] = true
					pairs = append(pairs, kv{k, v})
				}
			}
		}
	}
	if allStrings {
		out := make(map[string]any, len(pairs))
		for _, p := range pairs {
			out[p.k.(string)] = p.v
		}
		return out, nil
	}
	out := make(map[any]any, len(pairs))
	for _, p := range pairs {
		out[p.k] = p.v
	}
	return out, nil
}

// mergeSources flattens a `<<` value node into the mapping nodes it
// merges (a single mapping/alias, or a sequence of them).
func (c *nodeConverter) mergeSources(m *yaml.Node) []*yaml.Node {
	if m.Kind == yaml.SequenceNode {
		return m.Content
	}
	return []*yaml.Node{m}
}

// toStringOrAnyMap converts a converted value back to key/value pairs
// for merge handling.
func toStringOrAnyMap(v any) (map[any]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		out := make(map[any]any, len(m))
		for k, val := range m {
			out[k] = val
		}
		return out, true
	case map[any]any:
		return m, true
	}
	return nil, false
}

// parseDocument sniffs one document and dispatches to the Kubernetes or
// CloudFormation path. Anything else becomes a warning diagnostic.
// Spans carry the file and the document's real 1-based start line in
// the source (the YAML root node's line). This used to be the document
// INDEX + 1, which attributed every finding in a multi-document file
// to a line near the top of the file — e.g. a K8S-027 finding against
// the second of two same-name Deployments pointed at line 2 instead
// of the second document's actual start (R5: r5180/r5193).
func (p *parser) parseDocument(doc any, idx int, line int) []ir.Resource {
	if line <= 0 {
		line = idx + 1
	}
	span := ir.Span{File: p.path, StartLine: line, StartCol: 1}
	m, ok := asStringMap(doc)
	if !ok {
		p.unrecognized(idx, span)
		return nil
	}
	_, hasAV := m["apiVersion"].(string)
	kind, hasKind := m["kind"].(string)
	switch {
	case hasAV && hasKind:
		return []ir.Resource{p.k8sResource(m, kind, span)}
	case isCFN(m):
		return p.cfnResources(m, span)
	default:
		p.unrecognized(idx, span)
		return nil
	}
}

func (p *parser) unrecognized(idx int, span ir.Span) {
	p.diags = append(p.diags, ir.Diagnostic{
		Level:   "warning",
		Message: fmt.Sprintf("manifests: unrecognized document %d in %s; skipped", idx+1, p.path),
		Span:    span,
	})
}

// isCFN reports whether a document looks like a CloudFormation template:
// an explicit AWSTemplateFormatVersion, or a Resources mapping without
// Kubernetes markers.
func isCFN(m map[string]any) bool {
	if _, ok := m["AWSTemplateFormatVersion"]; ok {
		return true
	}
	if r, ok := m["Resources"]; ok {
		if _, ok := asStringMap(r); ok {
			return true
		}
	}
	return false
}

// k8sResource converts one Kubernetes document. The whole document becomes
// attributes so rules can navigate spec shapes; the resource name comes
// from metadata.name.
func (p *parser) k8sResource(m map[string]any, kind string, span ir.Span) ir.Resource {
	name := "unnamed"
	if md, ok := asStringMap(m["metadata"]); ok {
		if n, ok := md["name"].(string); ok && n != "" {
			name = n
		}
	}
	attrs := make(map[string]ir.Value, len(m))
	for k, v := range m {
		attrs[k] = p.value(v, span)
	}
	return ir.Resource{
		Type:       "k8s_" + kind,
		Name:       name,
		Provider:   "k8s",
		Attributes: attrs,
		Span:       span,
	}
}

// value converts a decoded scalar or collection to an ir.Value. YAML/JSON
// null becomes an explicit Unknown. Non-string map keys are skipped with a
// single warning per file.
func (p *parser) value(v any, span ir.Span) ir.Value {
	switch t := v.(type) {
	case nil:
		return ir.UnknownValue(span)
	case bool:
		return ir.Value{Raw: t, Known: true, Span: span}
	case string:
		return ir.Value{Raw: t, Known: true, Span: span}
	case int:
		return ir.Value{Raw: float64(t), Known: true, Span: span}
	case int64:
		return ir.Value{Raw: float64(t), Known: true, Span: span}
	case float64:
		return ir.Value{Raw: t, Known: true, Span: span}
	case []any:
		out := make([]ir.Value, 0, len(t))
		for _, e := range t {
			out = append(out, p.value(e, span))
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case map[string]any:
		out := make(map[string]ir.Value, len(t))
		for k, e := range t {
			out[k] = p.value(e, span)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case map[any]any:
		out := make(map[string]ir.Value, len(t))
		for k, e := range t {
			ks, ok := k.(string)
			if !ok {
				p.warnKeys(span)
				continue
			}
			out[ks] = p.value(e, span)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	default:
		return ir.UnknownValue(span)
	}
}

func (p *parser) warnKeys(span ir.Span) {
	if p.warnedKeys {
		return
	}
	p.warnedKeys = true
	p.diags = append(p.diags, ir.Diagnostic{
		Level:   "warning",
		Message: fmt.Sprintf("manifests: non-string map key skipped in %s", p.path),
		Span:    span,
	})
}

// strValue builds a known string value.
func (p *parser) strValue(s string, span ir.Span) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: span}
}

// asStringMap converts a decoded mapping to map[string]any. Non-string
// keys fail the conversion (the caller decides whether to warn or skip).
func asStringMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			ks, ok := k.(string)
			if !ok {
				return nil, false
			}
			out[ks] = val
		}
		return out, true
	}
	return nil, false
}
