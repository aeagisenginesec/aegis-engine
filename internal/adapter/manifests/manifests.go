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
		out = append(out, p.parseDocument(doc, i)...)
	}
	return out, p.diags, nil
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
func (p *parser) decode(src []byte) []any {
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
		return []any{doc}
	}
	var docs []any
	dec := yaml.NewDecoder(bytes.NewReader(src))
	for {
		var doc any
		if err := dec.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			p.diags = append(p.diags, ir.Diagnostic{
				Level:   "error",
				Message: fmt.Sprintf("manifests: invalid YAML: %v", err),
				Span:    ir.Span{File: p.path},
			})
			return nil
		}
		if doc == nil {
			continue // empty document (bare --- separator)
		}
		docs = append(docs, doc)
	}
	return docs
}

// parseDocument sniffs one document and dispatches to the Kubernetes or
// CloudFormation path. Anything else becomes a warning diagnostic.
// Spans carry the file and the 1-based document index: an approximation,
// documented as such, since YAML sub-spans are not tracked.
func (p *parser) parseDocument(doc any, idx int) []ir.Resource {
	span := ir.Span{File: p.path, StartLine: idx + 1, StartCol: 1}
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
