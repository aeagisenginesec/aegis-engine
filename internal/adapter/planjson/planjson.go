// Package planjson adapts `terraform show -json plan.tfplan` output into the
// Aegis canonical IR.
//
// This is read-only analysis of a plan file: nothing is executed. Sensitive
// values are redacted to UnknownValue at the boundary — plaintext secrets
// never enter the IR.
//
// Name/address mapping (documented contract):
//   - Resource.Type is the plan's resource type (e.g. "aws_subnet").
//   - Resource.Name is the module-qualified name: the plan's short name for
//     root-module resources (e.g. "data"), or "<module path>.<name>" for
//     child-module resources (e.g. "module.vpc.a").
//   - Consequently Resource.Address() is unique across modules. For root
//     resources it equals the plan address exactly; for child-module
//     resources it reads "<type>.<module path>.<name>".
//
// Plan JSON carries no source positions, so every Span is the file itself
// (1:1-1:1). JSON null (unknown at apply time) and sensitive-marked values
// both become UnknownValue.
package planjson

import (
	"encoding/json"
	"fmt"
	"strings"

	"aegis/internal/ir"
)

// Adapter implements ir.Adapter for Terraform plan JSON files.
type Adapter struct{}

// Name identifies the adapter.
func (Adapter) Name() string { return "terraform-plan" }

// Handles reports whether path looks like a Terraform plan JSON file.
// Narrow on purpose: a generic ".json" match would collide with future
// adapters (CloudFormation, Kubernetes manifests, ...).
func (Adapter) Handles(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".plan.json")
}

// fileSpan is the span used everywhere: plan JSON has no source positions.
func fileSpan(path string) ir.Span {
	return ir.Span{File: path, StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 1}
}

// --- plan JSON subset schema (DisallowUnknownFields intentionally off;
// the real schema is large and version-dependent) ---

type planFile struct {
	PlannedValues *planPlannedValues `json:"planned_values"`
}

type planPlannedValues struct {
	RootModule planModule `json:"root_module"`
}

type planModule struct {
	Address      string         `json:"address"`
	Resources    []planResource `json:"resources"`
	ChildModules []planModule   `json:"child_modules"`
}

type planResource struct {
	Address         string         `json:"address"`
	Type            string         `json:"type"`
	Name            string         `json:"name"`
	Values          map[string]any `json:"values"`
	SensitiveValues map[string]any `json:"sensitive_values"`
}

// Parse implements ir.Adapter.
func (Adapter) Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error) {
	var pf planFile
	if err := json.Unmarshal(src, &pf); err != nil {
		return nil, nil, fmt.Errorf("planjson: cannot decode %s: %w", path, err)
	}
	span := fileSpan(path)
	if pf.PlannedValues == nil {
		return nil, []ir.Diagnostic{{
			Level:   "warning",
			Message: "plan JSON has no planned_values; nothing to scan",
			Span:    span,
		}}, nil
	}
	var (
		out   []ir.Resource
		diags []ir.Diagnostic
	)
	var walk func(m planModule)
	walk = func(m planModule) {
		for _, pr := range m.Resources {
			res, ok := convertResource(pr, span)
			if !ok {
				diags = append(diags, ir.Diagnostic{
					Level:   "warning",
					Message: fmt.Sprintf("skipping resource with missing type or address (name %q)", pr.Name),
					Span:    span,
				})
				continue
			}
			out = append(out, res)
		}
		for _, c := range m.ChildModules {
			walk(c)
		}
	}
	walk(pf.PlannedValues.RootModule)
	return out, diags, nil
}

// convertResource maps one plan resource to IR. ok=false when the record is
// missing its type or address.
func convertResource(pr planResource, span ir.Span) (ir.Resource, bool) {
	if pr.Type == "" || pr.Address == "" {
		return ir.Resource{}, false
	}
	attrs := make(map[string]ir.Value, len(pr.Values))
	for k, v := range pr.Values {
		attrs[k] = toValue(v, pr.SensitiveValues[k], span)
	}
	return ir.Resource{
		Type:       pr.Type,
		Name:       qualifiedName(pr),
		Provider:   providerOf(pr.Type),
		Attributes: attrs,
		Span:       span,
	}, true
}

// qualifiedName derives the resource Name: the plan's short name for root
// resources, or "<module path>.<name>" for child-module resources, parsed
// from the authoritative plan address.
func qualifiedName(pr planResource) string {
	suffix := pr.Type + "." + pr.Name
	if pr.Name != "" && strings.HasSuffix(pr.Address, suffix) {
		if mod := strings.TrimSuffix(pr.Address[:len(pr.Address)-len(suffix)], "."); mod != "" {
			return mod + "." + pr.Name
		}
		return pr.Name
	}
	// Malformed address: stay identifiable rather than dropping the resource.
	if pr.Name != "" {
		return pr.Name
	}
	return pr.Address
}

// providerOf mirrors the terraform adapter: leading namespace of the type.
func providerOf(resType string) string {
	if i := strings.Index(resType, "_"); i > 0 {
		return resType[:i]
	}
	return resType
}

// toValue converts a decoded JSON value to IR. A sensitivity marker of true
// at the same position redacts the whole subtree to UnknownValue. JSON null
// (unknown at apply time) is also Unknown. Shapes encoding/json cannot
// produce fall through to Unknown defensively — this function never panics.
func toValue(raw, sens any, span ir.Span) ir.Value {
	if b, ok := sens.(bool); ok && b {
		return ir.UnknownValue(span)
	}
	switch v := raw.(type) {
	case nil:
		return ir.UnknownValue(span)
	case bool:
		return ir.Value{Raw: v, Known: true, Span: span}
	case string:
		return ir.Value{Raw: v, Known: true, Span: span}
	case float64:
		return ir.Value{Raw: v, Known: true, Span: span}
	case []any:
		var ss []any
		if sl, ok := sens.([]any); ok {
			ss = sl
		}
		out := make([]ir.Value, len(v))
		for i, e := range v {
			var es any
			if i < len(ss) {
				es = ss[i]
			}
			out[i] = toValue(e, es, span)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case map[string]any:
		sm, _ := sens.(map[string]any)
		out := make(map[string]ir.Value, len(v))
		for k, e := range v {
			out[k] = toValue(e, sm[k], span)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	default:
		return ir.UnknownValue(span)
	}
}
