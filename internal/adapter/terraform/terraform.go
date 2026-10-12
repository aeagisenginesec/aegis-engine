// Package terraform implements ir.Adapter for Terraform HCL native syntax.
//
// Milestone 1 scope:
//   - Parses `resource "TYPE" "NAME" { ... }` blocks into ir.Resource.
//   - Attribute values resolve only when they are pure static literals
//     (strings, numbers, bools, lists, objects, unary minus on numbers).
//     Anything referencing variables, locals, data sources, functions,
//     conditionals, or count/each becomes ir.UnknownValue — never guessed.
//   - Nested blocks become []ir.Value of map[string]ir.Value; repeats append.
//   - `data` blocks and every other block type are skipped without error
//     (data-source resolution is a Milestone 2 concern).
//   - `.tfvars` files are NOT handled (Handles returns false); variable
//     definitions are a Milestone 2 concern.
//
// Safety: parsing never executes anything. Expression evaluation uses an
// empty EvalContext plus a syntactic static-literal whitelist, and a
// recover() guard turns any unexpected evaluation panic into Unknown.
package terraform

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"aegis/internal/ir"
)

// Adapter parses Terraform (.tf) files into the canonical IR.
type Adapter struct{}

// Compile-time check that Adapter satisfies ir.Adapter.
var _ ir.Adapter = Adapter{}

// suppressCommentPrefix marks inline finding suppressions in HCL comments:
// `# aegis:skip=RULE-ID`, `# aegis:skip=A,B`, or `# aegis:skip=all`.
// A comment applies to a resource block when it sits on the line directly
// above the block or on the same line as the `resource` declaration.
const suppressCommentPrefix = "aegis:skip="

// scanSuppressComments maps 1-based line numbers to the rule IDs suppressed
// by an aegis:skip comment on that line. Both `#` and `//` comment styles
// are recognized. Malformed directives yield no suppressions (never panic).
func scanSuppressComments(src []byte) map[int][]string {
	out := map[int][]string{}
	for i, line := range strings.Split(string(src), "\n") {
		lineno := i + 1 // 1-based
		ids := parseSuppressComment(line)
		if len(ids) > 0 {
			out[lineno] = ids
		}
	}
	return out
}

// parseSuppressComment extracts suppressed rule IDs from one source line.
// Returns nil when the line carries no aegis:skip directive.
func parseSuppressComment(line string) []string {
	// Find the comment start: `#` or `//`. (A `#` inside a string literal
	// could false-positive; acceptable — directives are opt-in and the
	// worst case is a user-requested suppression being honored.)
	idx := strings.Index(line, "#")
	if idx < 0 {
		if j := strings.Index(line, "//"); j >= 0 {
			idx = j
		} else {
			return nil
		}
	}
	comment := line[idx+1:]
	if strings.HasPrefix(line[idx:], "//") {
		comment = line[idx+2:]
	}
	p := strings.Index(comment, suppressCommentPrefix)
	if p < 0 {
		return nil
	}
	rest := comment[p+len(suppressCommentPrefix):]
	// Directive ends at end of line; a `#` starting another comment also
	// terminates it (defensive, directives are normally line-final).
	if i := strings.Index(rest, "#"); i >= 0 {
		rest = rest[:i]
	}
	var ids []string
	for _, id := range strings.Split(rest, ",") {
		id = strings.TrimSpace(id)
		// Stop at the first whitespace-only remnant (trailing prose).
		if id == "" {
			continue
		}
		if strings.ContainsAny(id, " \t") {
			break
		}
		ids = append(ids, id)
	}
	return ids
}

// suppressRulesForBlock returns the suppressed rule IDs for a resource block
// starting at startLine: directives on the same line or the line directly
// above. Results are deduplicated, preserving first-seen order.
func suppressRulesForBlock(comments map[int][]string, startLine int) []string {
	var out []string
	seen := map[string]bool{}
	for _, lineno := range []int{startLine - 1, startLine} {
		for _, id := range comments[lineno] {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// New constructs the adapter (kept for the CLI wiring in cmd/aegis).
func New() *Adapter { return &Adapter{} }

// Name identifies the adapter.
func (Adapter) Name() string { return "terraform" }

// Handles reports whether this adapter parses the given path.
// Only native-syntax .tf files for M1; .tfvars is explicitly excluded.
func (Adapter) Handles(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".tf")
}

// Variable is a Terraform input variable declaration.
type Variable struct {
	Name string
	// Default is the static default value, or Unknown when the variable
	// has no default (or a non-static one). Span covers the default expr.
	Default ir.Value
	// Sensitive is true when the variable block sets sensitive = true.
	Sensitive bool
	Span      ir.Span
}

// ProviderReq is one entry of `terraform { required_providers { ... } }`:
// a provider version constraint for the module.
type ProviderReq struct {
	Name string // local name, e.g. "aws"
	// Source is the provider source address, e.g. "hashicorp/aws".
	// Empty when not statically known.
	Source string
	// Version is the version constraint string, e.g. "~> 5.0".
	// Empty when absent or not statically known (unknown -> "").
	Version string
	Span    ir.Span
}

// Module is one parsed .tf file: resources plus the declarations the
// semantics layer needs for Milestone 2 resolution (variables, locals,
// module calls).
type Module struct {
	Path        string
	Resources   []ir.Resource
	Variables   map[string]Variable
	Locals      map[string]ir.Value
	ModuleCalls []ModuleCall
	// SyntheticResources holds terraform_variable, terraform_locals, and
	// terraform_output pseudo-resources for secret-detection rules
	// (AEGIS-AWS-536/538/539). Kept separate from Resources so the
	// semantics layer (which counts infrastructure resources) is unaffected.
	SyntheticResources []ir.Resource
	// ProviderReqs holds `terraform { required_providers { ... } }` entries
	// (Milestone 5 supply-chain advisories). Sorted by Name.
	ProviderReqs []ProviderReq
}

// ModuleCall is a `module "NAME" { source = "...", ... }` block.
// Source holds the static source string, or "" when the source is not a
// static string literal. Inputs maps every other attribute (variable
// bindings, e.g. `cidr = var.vpc_cidr`) to its expression value —
// references are preserved for the semantics layer to resolve.
type ModuleCall struct {
	Name   string
	Source string
	Inputs map[string]ir.Value
	Span   ir.Span
}

// ParseModule parses one file into a Module: resources plus variable and
// local declarations. Diagnostics follow the same rules as Parse.
// Structural pre-validation (PreValidate) runs first: hopeless input
// (binary garbage, UTF-16, oversize, truncated, absurdly nested) fails
// fast with a clear hard error instead of a confusing parser diagnostic.
// lenientParseConfig parses src as native HCL, with a targeted recovery
// for single-line object constructors written without comma separators
// (e.g. { Effect = "Allow" Action = "s3:GetObject" }). Some generators and
// hand-written files omit the commas; the strict parser then reports
// "Missing attribute separator" and silently drops the remaining items,
// which mangles jsonencode() policy documents into empty statements.
//
// Recovery only triggers on files the strict parser already rejects:
// commas are inserted at the exact diagnostic positions and the source is
// re-parsed, iterating because the parser reports only the first missing
// separator per pass. If the repaired source parses cleanly it is used;
// otherwise the original partial result is returned unchanged. This is
// purely additive: files that parsed cleanly before are untouched.
func lenientParseConfig(src []byte, path string) (*hcl.File, hcl.Diagnostics) {
	f, diags := hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	fixed := append([]byte(nil), src...)
	// The parser reports only the first missing separator per pass, so
	// iterate. Bound the loop: each pass must fix at least one position.
	for i := 0; i < 32; i++ {
		offsets := missingSeparatorOffsets(diags)
		if len(offsets) == 0 {
			break
		}
		// Insert commas back-to-front so earlier offsets stay valid.
		for j := len(offsets) - 1; j >= 0; j-- {
			off := offsets[j]
			if off < 0 || off > len(fixed) {
				continue
			}
			fixed = append(fixed[:off:off], append([]byte{','}, fixed[off:]...)...)
		}
		var diags2 hcl.Diagnostics
		f, diags2 = hclsyntax.ParseConfig(fixed, path, hcl.Pos{Line: 1, Column: 1})
		if !diags2.HasErrors() {
			return f, diags2
		}
		diags = diags2
	}
	if diags.HasErrors() {
		// Recovery failed: fall back to the original strict parse so
		// behavior on unrecoverable files is unchanged.
		f, diags = hclsyntax.ParseConfig(src, path, hcl.Pos{Line: 1, Column: 1})
	}
	return f, diags
}

// missingSeparatorOffsets returns the deduplicated, sorted byte offsets at
// which the parser reported a missing attribute separator.
func missingSeparatorOffsets(diags hcl.Diagnostics) []int {
	seen := map[int]bool{}
	var out []int
	for _, d := range diags {
		if d.Summary != "Missing attribute separator" {
			continue
		}
		if d.Subject == nil {
			continue
		}
		off := d.Subject.Start.Byte
		if !seen[off] {
			seen[off] = true
			out = append(out, off)
		}
	}
	sort.Ints(out)
	return out
}

func (Adapter) ParseModule(path string, src []byte) (Module, []ir.Diagnostic, error) {
	if err := PreValidate(path, src); err != nil {
		return Module{}, nil, err
	}
	f, diags := lenientParseConfig(src, path)

	var out []ir.Diagnostic
	for _, d := range diags {
		if d.Severity != hcl.DiagError && d.Severity != hcl.DiagWarning {
			continue
		}
		level := "error"
		if d.Severity == hcl.DiagWarning {
			level = "warning"
		}
		msg := d.Summary
		if d.Detail != "" {
			msg += ": " + d.Detail
		}
		span := ir.Span{File: path}
		if d.Subject != nil {
			span = spanFromRange(path, *d.Subject)
		}
		out = append(out, ir.Diagnostic{Level: level, Message: msg, Span: span})
	}
	if f == nil {
		return Module{}, out, errors.New("terraform: unable to parse file as HCL")
	}
	mod := Module{Path: path, Variables: map[string]Variable{}, Locals: map[string]ir.Value{}}
	syn, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		out = append(out, ir.Diagnostic{Level: "warning",
			Message: "terraform: non-native HCL body; block enumeration skipped",
			Span:    ir.Span{File: path}})
		return mod, out, nil
	}
	// Inline suppressions: `# aegis:skip=RULE` comments on the line above
	// a resource block or on the block's own declaration line.
	suppressComments := scanSuppressComments(src)
	for _, b := range syn.Blocks {
		switch b.Type {
		case "resource":
			if len(b.Labels) != 2 {
				out = append(out, ir.Diagnostic{Level: "warning",
					Message: "terraform: resource block needs exactly 2 labels (type, name); skipped",
					Span:    spanFromRange(path, b.TypeRange)})
				continue
			}
			r := resourceFromBlock(path, b, &out)
			r.SuppressedRules = suppressRulesForBlock(suppressComments, b.TypeRange.Start.Line)
			mod.Resources = append(mod.Resources, r)
		case "data":
			// Supply-chain: emit data blocks as synthetic resources so rules
			// can inspect them (e.g. AEGIS-SC-007 flags data "external").
			if len(b.Labels) != 2 {
				continue
			}
			dr := resourceFromBlock(path, b, &out)
			dr.Type = "terraform_data"
			dr.Name = b.Labels[0] + "." + b.Labels[1]
			dr.Provider = "terraform"
			dr.SuppressedRules = suppressRulesForBlock(suppressComments, b.TypeRange.Start.Line)
			mod.Resources = append(mod.Resources, dr)
		case "variable":
			if len(b.Labels) != 1 {
				continue
			}
			v := Variable{Name: b.Labels[0], Span: blockSpan(path, b)}
			if attr, ok := b.Body.Attributes["default"]; ok {
				v.Default = valueFromExpr(path, attr.Expr)
			} else {
				v.Default = ir.UnknownValue(blockSpan(path, b))
			}
			if attr, ok := b.Body.Attributes["sensitive"]; ok {
				if bval, ok := valueFromExpr(path, attr.Expr).AsBool(); ok {
					v.Sensitive = bval
				}
			}
			mod.Variables[v.Name] = v
			// Synthetic resource so secret-detection rules can inspect
			// variable defaults (AEGIS-AWS-538).
			synthAttrs := map[string]ir.Value{"default": v.Default}
			if v.Sensitive {
				synthAttrs["sensitive"] = ir.Value{Raw: true, Known: true, Span: blockSpan(path, b)}
			}
			mod.SyntheticResources = append(mod.SyntheticResources, ir.Resource{
				Type:       "terraform_variable",
				Name:       v.Name,
				Provider:   "terraform",
				Attributes: synthAttrs,
				Span:       blockSpan(path, b),
			})
		case "locals":
			for name, attr := range b.Body.Attributes {
				mod.Locals[name] = valueFromExpr(path, attr.Expr)
			}
			// Synthetic resource so secret-detection rules can inspect
			// local values (AEGIS-AWS-539).
			localsAttrs := map[string]ir.Value{}
			for name, attr := range b.Body.Attributes {
				localsAttrs[name] = valueFromExpr(path, attr.Expr)
			}
			mod.SyntheticResources = append(mod.SyntheticResources, ir.Resource{
				Type:       "terraform_locals",
				Name:       "locals",
				Provider:   "terraform",
				Attributes: localsAttrs,
				Span:       blockSpan(path, b),
			})
		case "output":
			if len(b.Labels) != 1 {
				continue
			}
			// Synthetic resource so secret-detection rules can inspect
			// output values (AEGIS-AWS-536).
			outAttrs := map[string]ir.Value{}
			for name, attr := range b.Body.Attributes {
				outAttrs[name] = valueFromExpr(path, attr.Expr)
			}
			mod.SyntheticResources = append(mod.SyntheticResources, ir.Resource{
				Type:       "terraform_output",
				Name:       b.Labels[0],
				Provider:   "terraform",
				Attributes: outAttrs,
				Span:       blockSpan(path, b),
			})
		case "module":
			if len(b.Labels) != 1 {
				out = append(out, ir.Diagnostic{Level: "warning",
					Message: "terraform: module block needs exactly 1 label (name); skipped",
					Span:    spanFromRange(path, b.TypeRange)})
				continue
			}
			mc := ModuleCall{Name: b.Labels[0], Inputs: map[string]ir.Value{}, Span: blockSpan(path, b)}
			for name, attr := range b.Body.Attributes {
				v := valueFromExpr(path, attr.Expr)
				if name == "source" {
					if s, ok := v.AsString(); ok {
						mc.Source = s
					}
					continue
				}
				mc.Inputs[name] = v
			}
			mod.ModuleCalls = append(mod.ModuleCalls, mc)
		case "terraform":
			// Milestone 5: collect required_providers entries for
			// supply-chain advisory matching.
			for _, nb := range b.Body.Blocks {
				if nb.Type != "required_providers" {
					continue
				}
				for name, attr := range nb.Body.Attributes {
					pr := ProviderReq{
						Name: name,
						Span: spanFromRange(path, attr.Expr.Range()),
					}
					// The entry value is an object { source, version };
					// read statically-known string fields. valueFromExpr
					// may return an unknown container preserving refs, so
					// inspect Raw directly and take only known strings.
					if m, ok := valueFromExpr(path, attr.Expr).Raw.(map[string]ir.Value); ok {
						if s, ok := m["source"].AsString(); ok {
							pr.Source = s
						}
						if s, ok := m["version"].AsString(); ok {
							pr.Version = s
						}
					}
					mod.ProviderReqs = append(mod.ProviderReqs, pr)
				}
			}
			// Terraform-security rules (AEGIS-TF-*): expose the terraform
			// block and its backend as synthetic resources so the rule
			// engine can inspect backend encryption, locking, and version
			// pinning without a separate analysis path.
			mod.Resources = append(mod.Resources, terraformConfigResource(path, b, suppressComments))
			for _, nb := range b.Body.Blocks {
				if nb.Type != "backend" || len(nb.Labels) != 1 {
					continue
				}
				mod.Resources = append(mod.Resources, terraformBackendResource(path, nb, suppressComments, &out))
			}
		case "provider":
			// Terraform-security rules (AEGIS-TF-*): expose provider
			// blocks so rules can inspect provider-level safety flags
			// (e.g. skip_credentials_validation).
			if len(b.Labels) != 1 {
				out = append(out, ir.Diagnostic{Level: "warning",
					Message: "terraform: provider block needs exactly 1 label (name); skipped",
					Span:    spanFromRange(path, b.TypeRange)})
				continue
			}
			r := ir.Resource{
				Type:       "terraform_provider",
				Name:       b.Labels[0],
				Provider:   "terraform",
				Attributes: make(map[string]ir.Value),
				Span:       blockSpan(path, b),
			}
			attributesFromBody(path, b.Body, r.Attributes, &out)
			r.SuppressedRules = suppressRulesForBlock(suppressComments, b.TypeRange.Start.Line)
			mod.Resources = append(mod.Resources, r)
		}
	}
	// Deterministic order for advisory matching.
	sort.Slice(mod.ProviderReqs, func(i, j int) bool { return mod.ProviderReqs[i].Name < mod.ProviderReqs[j].Name })
	return mod, out, nil
}

// Parse converts HCL source into IR resources.
//
// HCL syntax errors become ir.Diagnostics (Level "error"); a hard error is
// returned only when the file cannot be parsed as HCL at all.
func (Adapter) Parse(path string, src []byte) ([]ir.Resource, []ir.Diagnostic, error) {
	mod, diags, err := Adapter{}.ParseModule(path, src)
	return mod.Resources, diags, err
}

// terraformConfigResource converts one `terraform { }` block into a
// synthetic ir.Resource of type "terraform_config" for the AEGIS-TF-*
// rules. required_providers entries are normalized into a sorted block
// list of {name, source, version} maps; version is absent when the entry
// has none and Unknown when it is not a static string.
func terraformConfigResource(path string, b *hclsyntax.Block, comments map[int][]string) ir.Resource {
	r := ir.Resource{
		Type:       "terraform_config",
		Name:       "terraform",
		Provider:   "terraform",
		Attributes: make(map[string]ir.Value),
		Span:       blockSpan(path, b),
	}
	if attr, ok := b.Body.Attributes["required_version"]; ok {
		r.Attributes["required_version"] = valueFromExpr(path, attr.Expr)
	}
	var provs []ir.Value
	for _, nb := range b.Body.Blocks {
		switch nb.Type {
		case "backend":
			if len(nb.Labels) == 1 {
				lspan := blockSpan(path, nb)
				if len(nb.LabelRanges) > 0 {
					lspan = spanFromRange(path, nb.LabelRanges[0])
				}
				r.Attributes["backend_type"] = ir.Value{
					Raw: nb.Labels[0], Known: true, Span: lspan,
				}
			}
		case "required_providers":
			for name, attr := range nb.Body.Attributes {
				aspan := spanFromRange(path, attr.Expr.Range())
				m := map[string]ir.Value{
					"name": {Raw: name, Known: true, Span: aspan},
				}
				if om, ok := valueFromExpr(path, attr.Expr).Raw.(map[string]ir.Value); ok {
					if sv, present := om["source"]; present {
						if s, ok := sv.AsString(); ok {
							m["source"] = ir.Value{Raw: s, Known: true, Span: sv.Span}
						}
					}
					if vv, present := om["version"]; present {
						if s, ok := vv.AsString(); ok {
							m["version"] = ir.Value{Raw: s, Known: true, Span: vv.Span}
						} else {
							m["version"] = ir.UnknownValue(vv.Span)
						}
					}
				}
				provs = append(provs, ir.Value{Raw: m, Known: true, Span: aspan})
			}
		}
	}
	sort.Slice(provs, func(i, j int) bool {
		mi, _ := provs[i].Raw.(map[string]ir.Value)
		mj, _ := provs[j].Raw.(map[string]ir.Value)
		var ni, nj string
		if v, ok := mi["name"]; ok {
			ni, _ = v.Raw.(string)
		}
		if v, ok := mj["name"]; ok {
			nj, _ = v.Raw.(string)
		}
		return ni < nj
	})
	if provs != nil {
		r.Attributes["required_providers"] = ir.Value{Raw: provs, Known: true, Span: blockSpan(path, b)}
	}
	r.SuppressedRules = suppressRulesForBlock(comments, b.TypeRange.Start.Line)
	return r
}

// terraformBackendResource converts one `backend "TYPE" { }` block (nested
// inside `terraform { }`) into a synthetic ir.Resource of type
// "terraform_backend" named after the backend type (e.g. "s3").
func terraformBackendResource(path string, b *hclsyntax.Block, comments map[int][]string, diags *[]ir.Diagnostic) ir.Resource {
	r := ir.Resource{
		Type:       "terraform_backend",
		Name:       b.Labels[0],
		Provider:   "terraform",
		Attributes: make(map[string]ir.Value),
		Span:       blockSpan(path, b),
	}
	attributesFromBody(path, b.Body, r.Attributes, diags)
	r.SuppressedRules = suppressRulesForBlock(comments, b.TypeRange.Start.Line)
	return r
}

// resourceFromBlock converts one `resource "TYPE" "NAME" { }` block.
// Constructs the adapter cannot model degrade to warning diagnostics
// appended to diags: dynamic blocks are not expanded, and count/for_each
// over unresolvable expressions are analyzed as a single instance.
func resourceFromBlock(path string, b *hclsyntax.Block, diags *[]ir.Diagnostic) ir.Resource {
	r := ir.Resource{
		Type:       b.Labels[0],
		Name:       b.Labels[1],
		Provider:   providerOf(b.Labels[0]),
		Attributes: make(map[string]ir.Value),
		Span: ir.Span{
			File:      path,
			StartLine: b.TypeRange.Start.Line,
			StartCol:  b.TypeRange.Start.Column,
			EndLine:   b.CloseBraceRange.End.Line,
			EndCol:    b.CloseBraceRange.End.Column,
		},
	}
	attributesFromBody(path, b.Body, r.Attributes, diags)
	// count/for_each decide how many instances a block creates. A static
	// value is fine (one logical instance is analyzed); an unresolvable
	// expression means the instance count is unknown — say so instead of
	// silently analyzing a single instance.
	for _, meta := range []string{"count", "for_each"} {
		if v, ok := r.Attributes[meta]; ok && !v.Known {
			*diags = append(*diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("terraform: %s uses %q with an unresolvable expression; analyzed as a single instance", r.Address(), meta),
				Span:    v.Span,
			})
		}
	}
	return r
}

// attributesFromBody fills attrs from a block body: plain attributes first,
// then nested blocks. Each nested block type becomes []ir.Value of
// map[string]ir.Value; repeated blocks append. On a name collision between
// an attribute and a block type, the block list wins (deterministic).
// A `dynamic` block cannot be expanded statically: it is kept verbatim
// under the "dynamic" key and a warning diagnostic is appended so the
// analysis gap is visible instead of silent.
func attributesFromBody(path string, body *hclsyntax.Body, attrs map[string]ir.Value, diags *[]ir.Diagnostic) {
	for name, attr := range body.Attributes {
		attrs[name] = valueFromExpr(path, attr.Expr)
	}
	for _, nb := range body.Blocks {
		if nb.Type == "dynamic" {
			label := ""
			if len(nb.Labels) > 0 {
				label = nb.Labels[0]
			}
			*diags = append(*diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("terraform: dynamic %q block is not expanded; its nested configuration is not analyzed", label),
				Span:    blockSpan(path, nb),
			})
		}
		m := make(map[string]ir.Value)
		attributesFromBody(path, nb.Body, m, diags)
		elem := ir.Value{Raw: m, Known: true, Span: blockSpan(path, nb)}
		if prev, ok := attrs[nb.Type]; ok {
			if list, ok := prev.AsList(); ok {
				attrs[nb.Type] = ir.Value{Raw: append(list, elem), Known: true, Span: prev.Span}
				continue
			}
		}
		attrs[nb.Type] = ir.Value{Raw: []ir.Value{elem}, Known: true, Span: blockSpan(path, nb)}
	}
}

// blockSpan covers a nested block from its type keyword to its closing brace.
func blockSpan(path string, b *hclsyntax.Block) ir.Span {
	return ir.Span{
		File:      path,
		StartLine: b.TypeRange.Start.Line,
		StartCol:  b.TypeRange.Start.Column,
		EndLine:   b.CloseBraceRange.End.Line,
		EndCol:    b.CloseBraceRange.End.Column,
	}
}

// providerOf infers the provider from the resource type's leading namespace:
// "aws_s3_bucket" -> "aws".
func providerOf(resType string) string {
	if i := strings.Index(resType, "_"); i > 0 {
		return resType[:i]
	}
	return resType
}

// emptyCtx has no variables and no functions, so any reference or call
// fails evaluation with diagnostics instead of resolving.
var emptyCtx = &hcl.EvalContext{}

// valueFromExpr converts an attribute expression to an ir.Value.
// Only pure static literals resolve to Known values; everything else is
// Unknown. A recover guard turns any unexpected evaluation panic into
// Unknown as well — parsing must never crash the scanner.
func valueFromExpr(path string, expr hcl.Expression) (v ir.Value) {
	span := spanFromRange(path, expr.Range())
	defer func() {
		if recover() != nil {
			v = ir.UnknownValue(span)
		}
	}()
	if !staticExpr(expr) {
		// Milestone 3: evaluate jsonencode() over static arguments so IAM
		// policy documents written as jsonencode({...}) become analyzable.
		// Only this one pure function is whitelisted; everything else below
		// stays unknown. Never executes arbitrary code.
		if call, ok := expr.(*hclsyntax.FunctionCallExpr); ok && call.Name == "jsonencode" && len(call.Args) == 1 {
			if staticExpr(call.Args[0]) {
				if s, ok := jsonEncodeStatic(call.Args[0]); ok {
					return ir.Value{Raw: s, Known: true, Span: span}
				}
			} else {
				// Non-static jsonencode (e.g., containing var.* refs):
				// preserve the inner structure with refs intact, marked for
				// JSON encoding after the semantics layer resolves variables.
				if inner, ok := refOrPartial(path, call.Args[0]); ok {
					inner.EncodeJSON = true
					inner.Span = span
					return inner
				}
			}
		}
		// Milestone 2: preserve reference paths so the semantics layer can
		// resolve them. A bare traversal keeps its Ref; tuples and objects
		// composed of static-or-ref elements keep their structure as an
		// Unknown container with the refs inside. Anything else stays a
		// plain unknown. (Containers stay Known=false: they are not fully
		// determined until the semantics pass resolves every child.)
		if v, ok := refOrPartial(path, expr); ok {
			return v
		}
		return ir.UnknownValue(span)
	}
	val, diags := expr.Value(emptyCtx)
	if diags.HasErrors() {
		return ir.UnknownValue(span)
	}
	return ctyToValue(val, span)
}

// refOrPartial converts a non-static expression into a reference-preserving
// unknown value: a bare traversal becomes an Unknown with its Ref path;
// tuples and objects whose elements are all static-or-ref become Unknown
// containers keeping the refs inside for the semantics layer. Anything else
// reports ok=false and the caller falls back to a plain Unknown.
func refOrPartial(path string, expr hcl.Expression) (ir.Value, bool) {
	span := spanFromRange(path, expr.Range())
	if trav, ok := expr.(*hclsyntax.ScopeTraversalExpr); ok {
		if ref, ok := traversalRef(trav.Traversal); ok {
			return ir.Value{Known: false, Span: span, Ref: ref}, true
		}
		return ir.Value{}, false
	}
	switch ex := expr.(type) {
	case *hclsyntax.TupleConsExpr:
		items := make([]ir.Value, 0, len(ex.Exprs))
		for _, e := range ex.Exprs {
			v, ok := staticOrRefOrPartial(path, e)
			if !ok {
				return ir.Value{}, false
			}
			items = append(items, v)
		}
		return ir.Value{Raw: items, Known: false, Span: span}, true
	case *hclsyntax.ObjectConsExpr:
		m := make(map[string]ir.Value, len(ex.Items))
		for _, item := range ex.Items {
			key, ok := staticKeyString(item.KeyExpr)
			if !ok {
				return ir.Value{}, false
			}
			v, ok := staticOrRefOrPartial(path, item.ValueExpr)
			if !ok {
				return ir.Value{}, false
			}
			m[key] = v
		}
		return ir.Value{Raw: m, Known: false, Span: span}, true
	}
	return ir.Value{}, false
}

// staticOrRefOrPartial resolves one composite element: static literals stay
// Known, bare traversals keep their Ref, nested tuples/objects recurse.
// ok=false means "not representable" — the whole composite stays Unknown.
func staticOrRefOrPartial(path string, e hcl.Expression) (ir.Value, bool) {
	if staticExpr(e) {
		span := spanFromRange(path, e.Range())
		val, diags := e.Value(emptyCtx)
		if diags.HasErrors() {
			return ir.Value{}, false
		}
		return ctyToValue(val, span), true
	}
	return refOrPartial(path, e)
}

// staticKeyString renders an object key as a string when it is statically
// known (bare identifier or quoted string); otherwise ok=false.
func staticKeyString(e hcl.Expression) (string, bool) {
	if k, ok := e.(*hclsyntax.ObjectConsKeyExpr); ok {
		if kw := hcl.ExprAsKeyword(k.Wrapped); kw != "" {
			return kw, true
		}
	}
	if staticExpr(e) {
		val, diags := e.Value(emptyCtx)
		if !diags.HasErrors() && val.IsKnown() && !val.IsNull() && val.Type() == cty.String {
			return val.AsString(), true
		}
	}
	return "", false
}

// traversalRef renders an HCL traversal as a dotted reference path:
// "var.region", "local.tags", "data.aws_ami.ubuntu.id", "each.key".
// Index steps with static string/number keys render as ["k"]/[n].
// Returns false for anything non-static.
func traversalRef(t hcl.Traversal) (string, bool) {
	var sb strings.Builder
	for i, p := range t {
		switch pt := p.(type) {
		case hcl.TraverseRoot:
			if i != 0 {
				return "", false
			}
			sb.WriteString(pt.Name)
		case hcl.TraverseAttr:
			sb.WriteString(".")
			sb.WriteString(pt.Name)
		case hcl.TraverseIndex:
			key := pt.Key
			if !key.IsKnown() || key.IsNull() {
				return "", false
			}
			switch {
			case key.Type() == cty.String:
				fmt.Fprintf(&sb, "[%q]", key.AsString())
			case key.Type() == cty.Number:
				f, _ := key.AsBigFloat().Float64()
				fmt.Fprintf(&sb, "[%d]", int(f))
			default:
				return "", false
			}
		default:
			return "", false
		}
	}
	if sb.Len() == 0 {
		return "", false
	}
	return sb.String(), true
}

// staticExpr reports whether e is a pure static literal: no traversals
// (var/local/data/each/count/self), no function calls, no conditionals, no
// operators except unary minus on a numeric literal, and no string
// interpolation. Anything else must stay Unknown — never guessed.
func staticExpr(e hcl.Expression) bool {
	switch ex := e.(type) {
	case *hclsyntax.LiteralValueExpr:
		return true
	case *hclsyntax.TemplateExpr:
		// A single-part template is just a literal ("hello", heredoc).
		if len(ex.Parts) != 1 {
			return false
		}
		return staticExpr(ex.Parts[0])
	case *hclsyntax.TemplateWrapExpr:
		return staticExpr(ex.Wrapped)
	case *hclsyntax.TupleConsExpr:
		for _, p := range ex.Exprs {
			if !staticExpr(p) {
				return false
			}
		}
		return true
	case *hclsyntax.ObjectConsExpr:
		for _, item := range ex.Items {
			if !staticObjectKey(item.KeyExpr) {
				return false
			}
			if !staticExpr(item.ValueExpr) {
				return false
			}
		}
		return true
	case *hclsyntax.UnaryOpExpr:
		// "-5": unary minus applied to a numeric literal is still a literal.
		if ex.Op == hclsyntax.OpNegate {
			if lit, ok := ex.Val.(*hclsyntax.LiteralValueExpr); ok {
				return lit.Val.Type() == cty.Number
			}
		}
		return false
	default:
		// ScopeTraversalExpr, FunctionCallExpr, ConditionalExpr,
		// BinaryOpExpr, AnonSymbolExpr, and anything unrecognized.
		return false
	}
}

// staticObjectKey allows bare-identifier keys ("name" in { name = "x" }),
// which HCL treats as literal strings, plus any otherwise-static key.
func staticObjectKey(e hcl.Expression) bool {
	if k, ok := e.(*hclsyntax.ObjectConsKeyExpr); ok {
		if hcl.ExprAsKeyword(k.Wrapped) != "" {
			return true
		}
	}
	return staticExpr(e)
}

// jsonEncodeStatic evaluates jsonencode() over an already-verified static
// expression, mirroring Terraform's encoding: strings, numbers, bools,
// lists, and objects become their JSON form. Returns ok=false if anything
// is not representable.
func jsonEncodeStatic(expr hcl.Expression) (string, bool) {
	val, diags := expr.Value(emptyCtx)
	if diags.HasErrors() {
		return "", false
	}
	goVal, ok := ctyToGo(val)
	if !ok {
		return "", false
	}
	b, err := json.Marshal(goVal)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// ctyToGo converts a known, non-null cty value to Go natives for JSON
// encoding. Unknown, null, or exotic types report ok=false.
func ctyToGo(val cty.Value) (any, bool) {
	val, _ = val.UnmarkDeep()
	if !val.IsKnown() || val.IsNull() {
		return nil, false
	}
	switch {
	case val.Type() == cty.String:
		return val.AsString(), true
	case val.Type() == cty.Bool:
		return val.True(), true
	case val.Type() == cty.Number:
		f, _ := val.AsBigFloat().Float64()
		return f, true
	case val.Type().IsTupleType() || val.Type().IsListType() || val.Type().IsSetType():
		out := make([]any, 0, val.LengthInt())
		for it := val.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			gv, ok := ctyToGo(ev)
			if !ok {
				return nil, false
			}
			out = append(out, gv)
		}
		return out, true
	case val.Type().IsObjectType() || val.Type().IsMapType():
		out := make(map[string]any)
		for it := val.ElementIterator(); it.Next(); {
			kv, ev := it.Element()
			gv, ok := ctyToGo(ev)
			if !ok {
				return nil, false
			}
			out[kv.AsString()] = gv
		}
		return out, true
	default:
		return nil, false
	}
}

// ctyToValue converts an evaluated cty value to an ir.Value.
// Null, unknown, or unrecognized types become Unknown.
func ctyToValue(val cty.Value, span ir.Span) ir.Value {
	unmarked, _ := val.UnmarkDeep()
	val = unmarked
	if !val.IsKnown() || val.IsNull() {
		return ir.UnknownValue(span)
	}
	switch {
	case val.Type() == cty.String:
		return ir.Value{Raw: val.AsString(), Known: true, Span: span}
	case val.Type() == cty.Bool:
		return ir.Value{Raw: val.True(), Known: true, Span: span}
	case val.Type() == cty.Number:
		f, _ := val.AsBigFloat().Float64()
		return ir.Value{Raw: f, Known: true, Span: span}
	case val.Type().IsTupleType() || val.Type().IsListType() || val.Type().IsSetType():
		out := make([]ir.Value, 0, val.LengthInt())
		known := true
		for it := val.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			cv := ctyToValue(ev, span)
			if !cv.Known {
				known = false
			}
			out = append(out, cv)
		}
		if !known {
			return ir.UnknownValue(span)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case val.Type().IsObjectType() || val.Type().IsMapType():
		out := make(map[string]ir.Value)
		known := true
		for it := val.ElementIterator(); it.Next(); {
			kv, ev := it.Element()
			cv := ctyToValue(ev, span)
			if !cv.Known {
				known = false
			}
			out[kv.AsString()] = cv
		}
		if !known {
			return ir.UnknownValue(span)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	default:
		return ir.UnknownValue(span)
	}
}

// spanFromRange maps an hcl.Range (1-based) onto an ir.Span.
func spanFromRange(path string, r hcl.Range) ir.Span {
	return ir.Span{
		File:      path,
		StartLine: r.Start.Line,
		StartCol:  r.Start.Column,
		EndLine:   r.End.Line,
		EndCol:    r.End.Column,
	}
}
