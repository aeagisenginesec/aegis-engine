// Package semantics resolves Terraform references into the canonical IR.
//
// Milestone 2 scope:
//   - Merge variable and local declarations across the files of one
//     directory into a Scope.
//   - Deep-substitute references (var.*, local.*) in resources, recursively
//     through lists and maps, with cycle detection and a hard recursion
//     bound. Anything else (data.*, each.*, count.*, self.*, module.*,
//     resource references) keeps its Ref intact for Milestone 3's graph.
//   - Expand local `module` blocks: parse the child directory, bind inputs
//     as variable overrides, prefix resource names, recurse with depth and
//     cycle guards. Remote sources are skipped with a diagnostic.
//
// The package never mutates its inputs and never panics: every recursion
// is bounded and every cycle terminates with the reference left unknown.
package semantics

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

// maxResolveDepth bounds all recursive resolution. Exceeding it leaves the
// value unknown with its Ref intact — never an infinite loop.
const maxResolveDepth = 32

// defaultMaxModuleDepth is used by ExpandModules when maxDepth <= 0.
const defaultMaxModuleDepth = 2

// Scope holds the resolved declarations of one directory: variables (by
// name, unknown when no static default) and locals.
type Scope struct {
	Variables map[string]ir.Value
	Locals    map[string]ir.Value
	// PolicyDocs indexes data.aws_iam_policy_document resources by their
	// full data address ("aws_iam_policy_document.NAME") so references like
	// data.aws_iam_policy_document.NAME.json can be resolved to the
	// constructed policy JSON. Populated by MergeModules.
	PolicyDocs map[string]ir.Resource
}

// MergeModules merges variable and local declarations across files of one
// directory into a Scope. On duplicate names the file that sorts later by
// path wins; iteration is path-sorted so the result is deterministic.
// Variable values are the declared defaults as parsed (static defaults are
// Known; missing or non-static defaults stay unknown, possibly with a Ref
// for the resolver to follow lazily).
func MergeModules(mods []terraform.Module) Scope {
	sorted := make([]terraform.Module, len(mods))
	copy(sorted, mods)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	s := Scope{
		Variables:  make(map[string]ir.Value),
		Locals:     make(map[string]ir.Value),
		PolicyDocs: make(map[string]ir.Resource),
	}
	for _, m := range sorted {
		for _, name := range sortedKeysOf(m.Variables) {
			s.Variables[name] = m.Variables[name].Default
		}
		for _, name := range sortedKeysOf(m.Locals) {
			s.Locals[name] = m.Locals[name]
		}
		// Index IAM policy document data sources for policy JSON
		// resolution. Data blocks arrive as synthetic terraform_data
		// resources named "<data-type>.<name>".
		for _, r := range m.Resources {
			if r.Type == "terraform_data" && strings.HasPrefix(r.Name, "aws_iam_policy_document.") {
				s.PolicyDocs[r.Name] = r
			}
		}
	}
	return s
}

// ResolveResources deep-substitutes every reference in resources against s
// and returns new resources; the inputs are never mutated.
//
//   - `var.NAME` resolves to the variable's default when known, otherwise
//     the reference is kept unknown with its Ref intact.
//   - `local.NAME` resolves recursively (locals may reference vars or other
//     locals). Reference cycles resolve to unknown and always terminate.
//   - Everything else (data.*, each.*, count.*, self.*, module.*,
//     resource references) is kept unknown with the Ref intact for M3.
//   - Substitution recurses into []ir.Value and map[string]ir.Value
//     containers. Resolved values keep the use-site span.
//
// Resolution is deterministic and idempotent: resolving twice yields the
// same output.
func (s Scope) ResolveResources(resources []ir.Resource) []ir.Resource {
	out := make([]ir.Resource, 0, len(resources))
	for _, r := range resources {
		c := r
		c.Attributes = make(map[string]ir.Value, len(r.Attributes))
		for _, k := range sortedValueKeys(r.Attributes) {
			c.Attributes[k] = s.resolveValue(r.Attributes[k], map[string]bool{}, 0)
		}
		out = append(out, c)
	}
	return out
}

// resolveValue resolves one value. localsSeen tracks the local names on the
// current resolution chain for cycle detection; depth bounds total recursion.
func (s Scope) resolveValue(v ir.Value, localsSeen map[string]bool, depth int) ir.Value {
	if depth > maxResolveDepth {
		return v
	}
	if !v.IsRef() {
		// Not a reference: resolve children inside containers. A container
		// whose children all resolve becomes Known (upgrade only — never
		// downgrade an already-Known container, e.g. nested blocks whose
		// leaves the rules inspect individually).
		switch raw := v.Raw.(type) {
		case []ir.Value:
			items := make([]ir.Value, len(raw))
			allKnown := true
			for i, e := range raw {
				items[i] = s.resolveValue(e, localsSeen, depth+1)
				if !items[i].Known {
					allKnown = false
				}
			}
			v.Raw = items
			if allKnown {
				v.Known = true
			}
			return s.maybeEncodeJSON(v)
		case map[string]ir.Value:
			m := make(map[string]ir.Value, len(raw))
			allKnown := true
			for _, k := range sortedValueKeys(raw) {
				m[k] = s.resolveValue(raw[k], localsSeen, depth+1)
				if !m[k].Known {
					allKnown = false
				}
			}
			v.Raw = m
			if allKnown {
				v.Known = true
			}
			return s.maybeEncodeJSON(v)
		default:
			return s.maybeEncodeJSON(v)
		}
	}
	head, rest, ok := splitRef(v.Ref)
	if !ok {
		return v
	}
	switch head {
	case "var":
		target, ok := s.Variables[rest]
		if !ok {
			return v // undeclared variable: keep unknown
		}
		return s.substitute(v, target, localsSeen, depth+1)
	case "local":
		if localsSeen[rest] {
			return v // reference cycle: keep unknown
		}
		target, ok := s.Locals[rest]
		if !ok {
			return v // undeclared local: keep unknown
		}
		localsSeen[rest] = true
		defer delete(localsSeen, rest)
		return s.substitute(v, target, localsSeen, depth+1)
	case "data":
		// data.aws_iam_policy_document.NAME.json resolves to the
		// constructed policy JSON document. Other data references stay
		// unknown with Ref intact.
		if policyJSON, ok := s.resolvePolicyDocumentRef(rest, localsSeen, depth+1); ok {
			return ir.Value{Raw: policyJSON, Known: true, Span: v.Span}
		}
		return v
	default:
		// data.*, each.*, count.*, self.*, module.*, terraform.*, path.*,
		// and resource references: unknown for now, Ref intact for M3.
		return v
	}
}

// substitute resolves target and, when it becomes known, returns its raw
// value at the use-site span. Otherwise the original reference is kept.
func (s Scope) substitute(use, target ir.Value, localsSeen map[string]bool, depth int) ir.Value {
	r := s.resolveValue(target, localsSeen, depth)
	if r.Known {
		return ir.Value{Raw: r.Raw, Known: true, Span: use.Span}
	}
	return use
}

// splitRef splits "var.region" into ("var", "region"). Refs without a dot
// (or with an empty head) are not resolvable references.
func splitRef(ref string) (head, rest string, ok bool) {
	i := strings.Index(ref, ".")
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// ExpandModules expands local `module` blocks found in mods.
//
// For each `module "NAME" { source = "./rel", inputs... }`:
//   - the child directory is parsed with adapter.ParseModule,
//   - input attributes are resolved against the parent scope and bound as
//     variable overrides (inputs win over declared defaults),
//   - child resources are resolved against the child scope and renamed to
//     `module.NAME.<orig>`,
//   - nested module blocks recurse with depth+1.
//
// Guards: maxDepth <= 0 means the default (2); exceeding it, remote or
// non-static sources, unreadable directories, and module cycles all produce
// a warning diagnostic and are skipped. Only expanded child resources are
// returned — callers combine them with their own resolved root resources.
// Output order is deterministic (sorted paths, names, and inputs).
func ExpandModules(rootDir string, mods []terraform.Module, adapter *terraform.Adapter, maxDepth int) ([]ir.Resource, []ir.Diagnostic) {
	if maxDepth <= 0 {
		maxDepth = defaultMaxModuleDepth
	}
	if adapter == nil {
		adapter = &terraform.Adapter{}
	}
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		absRoot = rootDir
	}
	rootScope := MergeModules(mods)

	sorted := make([]terraform.Module, len(mods))
	copy(sorted, mods)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })

	// Only expand module calls from modules located directly in the
	// scan root. Calls in nested modules are expanded by recursion from
	// the root call (expandCall passes the child's own directory as the
	// base for its nested calls), with correct relative resolution.
	//
	// Expanding every discovered module's calls against the scan root
	// was a scan-boundary escape: a nested module's `source = "../x"`
	// resolved to <parent-of-target>/x, so scanning target/ could
	// ingest resources from a sibling directory the user never asked
	// to scan (verified: target/sub/m calling "../secret" pulled in
	// ../secret/main.tf as module.s.*), and every nested call that
	// did not happen to resolve produced a spurious "cannot read
	// directory" warning naming the wrong path.
	//
	// Limit (documented, not silent): an independent stack in a
	// subdirectory of the target (no .tf files at the target root
	// calling into it) has its module calls left unexpanded — its
	// resources are still scanned as files, but without module-input
	// binding. Scan the stack directory itself to expand its modules.
	// Root-level relative sources (e.g. the root module calling
	// "../shared") are still honored: they are part of the scanned
	// stack by definition.
	var out []ir.Resource
	var diags []ir.Diagnostic
	for _, m := range sorted {
		if dirAbs, err := filepath.Abs(filepath.Dir(m.Path)); err != nil || dirAbs != absRoot {
			continue // nested module: handled by recursion from the root call
		}
		calls := make([]terraform.ModuleCall, len(m.ModuleCalls))
		copy(calls, m.ModuleCalls)
		sort.Slice(calls, func(i, j int) bool { return calls[i].Name < calls[j].Name })
		for _, mc := range calls {
			r, d := expandCall(absRoot, "", mc, adapter, rootScope, maxDepth, 1, []string{absRoot})
			out = append(out, r...)
			diags = append(diags, d...)
		}
	}
	return out, diags
}

// expandCall expands one module call. modPath is the dotted ancestry of
// enclosing modules ("" at the root), so nested resources get full
// Terraform-style addresses like module.l1.module.l2.aws_x.two. chain
// holds the absolute directory paths on the current expansion stack for
// cycle detection.
func expandCall(parentDir, modPath string, mc terraform.ModuleCall, adapter *terraform.Adapter, parentScope Scope, maxDepth, depth int, chain []string) ([]ir.Resource, []ir.Diagnostic) {
	var diags []ir.Diagnostic
	deny := func(level, msg string) ([]ir.Resource, []ir.Diagnostic) {
		return nil, append(diags, ir.Diagnostic{Level: level, Message: msg, Span: mc.Span})
	}
	if depth > maxDepth {
		return deny("warning", fmt.Sprintf("semantics: module %q exceeds max depth %d; skipped", mc.Name, maxDepth))
	}
	if mc.Source == "" {
		return deny("warning", fmt.Sprintf("semantics: module %q source is not a static string; skipped", mc.Name))
	}
	if !isLocalSource(mc.Source) {
		return deny("warning", fmt.Sprintf("semantics: module %q has remote source %q; skipped", mc.Name, mc.Source))
	}
	absChild, err := filepath.Abs(filepath.Join(parentDir, mc.Source))
	if err != nil {
		return deny("warning", fmt.Sprintf("semantics: module %q: cannot resolve path: %v", mc.Name, err))
	}
	for _, c := range chain {
		if c == absChild {
			return deny("warning", fmt.Sprintf("semantics: module cycle detected at %q; skipped", mc.Name))
		}
	}
	entries, err := os.ReadDir(absChild)
	if err != nil {
		return deny("warning", fmt.Sprintf("semantics: module %q: cannot read directory %s: %v", mc.Name, absChild, err))
	}
	var tfFiles []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(e.Name()), ".tf") {
			tfFiles = append(tfFiles, filepath.Join(absChild, e.Name()))
		}
	}
	sort.Strings(tfFiles)
	if len(tfFiles) == 0 {
		return deny("warning", fmt.Sprintf("semantics: module %q: no .tf files in %s", mc.Name, absChild))
	}
	var childMods []terraform.Module
	for _, f := range tfFiles {
		src, err := os.ReadFile(f)
		if err != nil {
			diags = append(diags, ir.Diagnostic{Level: "warning",
				Message: fmt.Sprintf("semantics: module %q: cannot read %s: %v", mc.Name, f, err),
				Span:    mc.Span})
			continue
		}
		mod, d, err := adapter.ParseModule(f, src)
		diags = append(diags, d...)
		if err != nil {
			diags = append(diags, ir.Diagnostic{Level: "warning",
				Message: fmt.Sprintf("semantics: module %q: parse error in %s: %v", mc.Name, f, err),
				Span:    mc.Span})
			continue
		}
		childMods = append(childMods, mod)
	}
	if len(childMods) == 0 {
		return nil, diags
	}

	childScope := MergeModules(childMods)
	// Bind inputs: resolve each input against the parent scope, then
	// override the child's variable of the same name.
	for _, name := range sortedValueKeys(mc.Inputs) {
		childScope.Variables[name] = parentScope.resolveValue(mc.Inputs[name], map[string]bool{}, 0)
	}

	var out []ir.Resource
	fullPath := "module." + mc.Name
	if modPath != "" {
		fullPath = modPath + ".module." + mc.Name
	}
	// Collect all resources first, then rename with reference rewriting.
	// When a resource `aws_s3_bucket.data` becomes `module.m.aws_s3_bucket.data`,
	// any intra-module reference like `aws_s3_bucket.data.id` must be rewritten
	// to `aws_s3_bucket.module.m.data.id`, otherwise CheckAll companion
	// correlation breaks for expanded modules.
	var collected []ir.Resource
	for _, cm := range childMods {
		resolved := childScope.ResolveResources(cm.Resources)
		expandedDyn, dynDiags := childScope.ExpandDynamicBlocks(resolved)
		diags = append(diags, dynDiags...)
		collected = append(collected, expandedDyn...)
	}
	// Build old address -> new address map.
	rename := make(map[string]string, len(collected))
	for _, r := range collected {
		oldAddr := r.Type + "." + r.Name
		newName := fullPath + "." + r.Name
		rename[oldAddr] = r.Type + "." + newName
	}
	// Rename and rewrite refs.
	for _, r := range collected {
		r.Name = fullPath + "." + r.Name
		r.Attributes = rewriteRefs(r.Attributes, rename)
		out = append(out, r)
	}
	// Recurse into nested module calls with an extended cycle chain.
	newChain := make([]string, 0, len(chain)+1)
	newChain = append(newChain, chain...)
	newChain = append(newChain, absChild)
	for _, cm := range childMods {
		calls := make([]terraform.ModuleCall, len(cm.ModuleCalls))
		copy(calls, cm.ModuleCalls)
		sort.Slice(calls, func(i, j int) bool { return calls[i].Name < calls[j].Name })
		for _, nc := range calls {
			r, d := expandCall(absChild, fullPath, nc, adapter, childScope, maxDepth, depth+1, newChain)
			out = append(out, r...)
			diags = append(diags, d...)
		}
	}
	return out, diags
}

// rewriteRefs recursively rewrites resource references in attributes
// according to the rename map (old address -> new address).
// A ref like "aws_s3_bucket.data.id" becomes "aws_s3_bucket.module.m.data.id"
// when the rename map contains "aws_s3_bucket.data" -> "aws_s3_bucket.module.m.data".
func rewriteRefs(attrs map[string]ir.Value, rename map[string]string) map[string]ir.Value {
	if len(rename) == 0 {
		return attrs
	}
	out := make(map[string]ir.Value, len(attrs))
	for k, v := range attrs {
		out[k] = rewriteValueRefs(v, rename)
	}
	return out
}

func rewriteValueRefs(v ir.Value, rename map[string]string) ir.Value {
	if v.Ref != "" {
		if newRef, ok := rewriteRefString(v.Ref, rename); ok {
			v.Ref = newRef
		}
	}
	switch raw := v.Raw.(type) {
	case []ir.Value:
		items := make([]ir.Value, len(raw))
		for i, item := range raw {
			items[i] = rewriteValueRefs(item, rename)
		}
		v.Raw = items
	case map[string]ir.Value:
		m := make(map[string]ir.Value, len(raw))
		for k, item := range raw {
			m[k] = rewriteValueRefs(item, rename)
		}
		v.Raw = m
	}
	return v
}

// rewriteRefString rewrites a reference like "aws_s3_bucket.data.id" using
// the rename map. It matches the longest resource address prefix.
func rewriteRefString(ref string, rename map[string]string) (string, bool) {
	bestOld := ""
	bestNew := ""
	for oldAddr, newAddr := range rename {
		// Match "oldAddr" or "oldAddr." prefix (for attribute access like ".id")
		if ref == oldAddr || strings.HasPrefix(ref, oldAddr+".") {
			if len(oldAddr) > len(bestOld) {
				bestOld = oldAddr
				bestNew = newAddr
			}
		}
	}
	if bestOld == "" {
		return ref, false
	}
	return bestNew + ref[len(bestOld):], true
}

// maybeEncodeJSON JSON-encodes a value marked with EncodeJSON (from
// jsonencode() with non-static args) once its inner structure is fully
// resolved. Returns the value unchanged if not marked or not yet known.
func (s Scope) maybeEncodeJSON(v ir.Value) ir.Value {
	if !v.EncodeJSON || !v.Known {
		return v
	}
	goVal := valueToGo(v.Raw)
	if goVal == nil && v.Raw != nil {
		return v // not encodable; leave as-is
	}
	b, err := json.Marshal(goVal)
	if err != nil {
		return v
	}
	return ir.Value{Raw: string(b), Known: true, Span: v.Span}
}

// valueToGo converts an ir.Value Raw structure to Go natives for JSON encoding.
func valueToGo(raw any) any {
	switch r := raw.(type) {
	case []ir.Value:
		out := make([]any, len(r))
		for i, item := range r {
			if !item.Known {
				return nil
			}
			out[i] = valueToGo(item.Raw)
		}
		return out
	case map[string]ir.Value:
		out := make(map[string]any, len(r))
		for k, item := range r {
			if !item.Known {
				return nil
			}
			out[k] = valueToGo(item.Raw)
		}
		return out
	case string, bool, float64:
		return r
	default:
		return r
	}
}

// isLocalSource reports whether a module source is a local path.
func isLocalSource(src string) bool {
	return src == "." || src == ".." ||
		strings.HasPrefix(src, "./") || strings.HasPrefix(src, "../") ||
		filepath.IsAbs(src)
}

func sortedValueKeys(m map[string]ir.Value) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// IAM policy document data sources
// ---------------------------------------------------------------------------

// resolvePolicyDocumentRef resolves "aws_iam_policy_document.NAME.json" to
// the constructed policy JSON string. Returns ok=false for anything else,
// leaving the reference unknown.
func (s Scope) resolvePolicyDocumentRef(rest string, localsSeen map[string]bool, depth int) (string, bool) {
	parts := strings.Split(rest, ".")
	if len(parts) != 3 || parts[0] != "aws_iam_policy_document" || parts[2] != "json" {
		return "", false
	}
	doc, ok := s.PolicyDocs[parts[0]+"."+parts[1]]
	if !ok {
		return "", false
	}
	return s.buildPolicyDocument(doc, localsSeen, depth)
}

// buildPolicyDocument constructs an IAM policy JSON document from a
// data.aws_iam_policy_document resource's statement blocks. Statement
// attributes are resolved against the scope first (they may reference
// variables). Returns ok=false if any statement field needed for the
// document is unresolvable — the reference stays unknown rather than
// producing a wrong policy.
func (s Scope) buildPolicyDocument(doc ir.Resource, localsSeen map[string]bool, depth int) (string, bool) {
	stmts, ok := doc.Attributes["statement"]
	if !ok {
		return "", false
	}
	stmtList, ok := stmts.AsList()
	if !ok || len(stmtList) == 0 {
		return "", false
	}
	statements := []any{}
	for _, st := range stmtList {
		m, ok := st.Raw.(map[string]ir.Value)
		if !ok {
			return "", false
		}
		// Resolve each statement field against the scope.
		rm := make(map[string]ir.Value, len(m))
		for _, k := range sortedValueKeys(m) {
			rm[k] = s.resolveValue(m[k], copySeen(localsSeen), depth+1)
		}
		stmt := map[string]any{}
		effect, ok := rm["effect"].AsString()
		if !ok {
			return "", false
		}
		stmt["Effect"] = effect
		if sid, ok := rm["sid"].AsString(); ok {
			stmt["Sid"] = sid
		}
		for _, pair := range [][2]string{
			{"actions", "Action"}, {"not_actions", "NotAction"},
			{"resources", "Resource"}, {"not_resources", "NotResource"},
		} {
			if v, present := rm[pair[0]]; present {
				if gv := valueToGo(v.Raw); gv != nil {
					stmt[pair[1]] = gv
				} else {
					return "", false
				}
			}
		}
		if pv, present := rm["principals"]; present {
			plist, ok := pv.AsList()
			if !ok {
				return "", false
			}
			principal := map[string]any{}
			for _, p := range plist {
				pm, ok := p.Raw.(map[string]ir.Value)
				if !ok {
					return "", false
				}
				ptype, ok := pm["type"].AsString()
				if !ok {
					return "", false
				}
				if gv := valueToGo(pm["identifiers"].Raw); gv != nil {
					principal[ptype] = gv
				} else {
					return "", false
				}
			}
			if len(principal) > 0 {
				stmt["Principal"] = principal
			}
		}
		if cv, present := rm["condition"]; present {
			clist, ok := cv.AsList()
			if !ok {
				return "", false
			}
			cond := map[string]any{}
			for _, c := range clist {
				cm, ok := c.Raw.(map[string]ir.Value)
				if !ok {
					return "", false
				}
				test, ok := cm["test"].AsString()
				if !ok {
					return "", false
				}
				variable, ok := cm["variable"].AsString()
				if !ok {
					return "", false
				}
				vals := valueToGo(cm["values"].Raw)
				if vals == nil {
					return "", false
				}
				if _, exists := cond[test]; !exists {
					cond[test] = map[string]any{}
				}
				cond[test].(map[string]any)[variable] = vals
			}
			if len(cond) > 0 {
				stmt["Condition"] = cond
			}
		}
		statements = append(statements, stmt)
	}
	out := map[string]any{
		"Version":   "2012-10-17",
		"Statement": statements,
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// copySeen copies the locals cycle-detection set for independent branches.
func copySeen(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Dynamic block expansion
// ---------------------------------------------------------------------------

// ExpandDynamicBlocks expands Terraform `dynamic` blocks into concrete nested
// blocks. It must run after ResolveResources so for_each expressions
// referencing variables are resolved. For each dynamic block:
//
//   - for_each resolving to a known list/map: the content block is replicated
//     once per element, with `<label>.value` and `<label>.key` references
//     substituted. Expanded blocks are appended to the target block type.
//   - for_each unresolvable: the block is left in place and a warning
//     diagnostic is emitted (never silently skipped).
//
// The input resources are never mutated; expanded copies are returned.
// Deterministic: expansion order follows resource and block order.
func (s Scope) ExpandDynamicBlocks(resources []ir.Resource) ([]ir.Resource, []ir.Diagnostic) {
	var diags []ir.Diagnostic
	out := make([]ir.Resource, 0, len(resources))
	for _, r := range resources {
		c := r
		dynVal, ok := r.Attributes["dynamic"]
		if !ok {
			out = append(out, c)
			continue
		}
		dynList, ok := dynVal.AsList()
		if !ok || len(dynList) == 0 {
			out = append(out, c)
			continue
		}
		c.Attributes = make(map[string]ir.Value, len(r.Attributes))
		for _, k := range sortedValueKeys(r.Attributes) {
			if k == "dynamic" {
				continue
			}
			c.Attributes[k] = r.Attributes[k]
		}
		var unexpanded []ir.Value
		for _, d := range dynList {
			dm, ok := d.Raw.(map[string]ir.Value)
			if !ok {
				unexpanded = append(unexpanded, d)
				continue
			}
			label, _ := dm["__label"].AsString()
			if label == "" {
				unexpanded = append(unexpanded, d)
				continue
			}
			forEach, ok := dm["for_each"]
			if !ok {
				diags = append(diags, ir.Diagnostic{
					Level:   "warning",
					Message: fmt.Sprintf("terraform: dynamic %q block has no for_each; not expanded", label),
					Span:    d.Span,
				})
				unexpanded = append(unexpanded, d)
				continue
			}
			forEach = s.resolveValue(forEach, map[string]bool{}, 0)
			items, keys, ok := dynamicItems(forEach)
			if !ok {
				diags = append(diags, ir.Diagnostic{
					Level:   "warning",
					Message: fmt.Sprintf("terraform: dynamic %q block has unresolvable for_each; its nested configuration is not analyzed", label),
					Span:    forEach.Span,
				})
				unexpanded = append(unexpanded, d)
				continue
			}
			contentVal, ok := dm["content"]
			if !ok {
				unexpanded = append(unexpanded, d)
				continue
			}
			contentList, ok := contentVal.AsList()
			if !ok || len(contentList) == 0 {
				unexpanded = append(unexpanded, d)
				continue
			}
			contentMap, ok := contentList[0].Raw.(map[string]ir.Value)
			if !ok {
				unexpanded = append(unexpanded, d)
				continue
			}
			for i, item := range items {
				expanded := substituteIterator(contentMap, label, keys[i], item)
				elem := ir.Value{Raw: expanded, Known: true, Span: d.Span}
				if prev, exists := c.Attributes[label]; exists {
					if prevList, ok := prev.AsList(); ok {
						c.Attributes[label] = ir.Value{Raw: append(prevList, elem), Known: true, Span: prev.Span}
						continue
					}
				}
				c.Attributes[label] = ir.Value{Raw: []ir.Value{elem}, Known: true, Span: d.Span}
			}
		}
		if len(unexpanded) > 0 {
			c.Attributes["dynamic"] = ir.Value{Raw: unexpanded, Known: true, Span: dynVal.Span}
		}
		out = append(out, c)
	}
	return out, diags
}

// dynamicItems converts a resolved for_each value into parallel items/keys
// slices. Lists yield index keys; maps yield their keys. Anything else
// (unknown, non-iterable) reports ok=false.
func dynamicItems(v ir.Value) (items []ir.Value, keys []ir.Value, ok bool) {
	if !v.Known {
		return nil, nil, false
	}
	span := v.Span
	switch raw := v.Raw.(type) {
	case []ir.Value:
		for i, item := range raw {
			if !item.Known {
				return nil, nil, false
			}
			items = append(items, item)
			keys = append(keys, ir.Value{Raw: float64(i), Known: true, Span: span})
		}
		return items, keys, true
	case map[string]ir.Value:
		for _, k := range sortedValueKeys(raw) {
			if !raw[k].Known {
				return nil, nil, false
			}
			items = append(items, raw[k])
			keys = append(keys, ir.Value{Raw: k, Known: true, Span: span})
		}
		return items, keys, true
	default:
		return nil, nil, false
	}
}

// substituteIterator deep-copies a content block map, replacing references
// to `<label>.value` with item and `<label>.key` with key. All other values
// pass through unchanged.
func substituteIterator(m map[string]ir.Value, label string, key, item ir.Value) map[string]ir.Value {
	out := make(map[string]ir.Value, len(m))
	for _, k := range sortedValueKeys(m) {
		if k == "__label" {
			continue
		}
		out[k] = substituteIteratorValue(m[k], label, key, item)
	}
	return out
}

func substituteIteratorValue(v ir.Value, label string, key, item ir.Value) ir.Value {
	if v.IsRef() {
		switch v.Ref {
		case label + ".value":
			return ir.Value{Raw: item.Raw, Known: item.Known, Span: v.Span}
		case label + ".key":
			return ir.Value{Raw: key.Raw, Known: key.Known, Span: v.Span}
		default:
			return v
		}
	}
	switch raw := v.Raw.(type) {
	case []ir.Value:
		items := make([]ir.Value, len(raw))
		for i, e := range raw {
			items[i] = substituteIteratorValue(e, label, key, item)
		}
		v.Raw = items
		return v
	case map[string]ir.Value:
		m := make(map[string]ir.Value, len(raw))
		for _, k := range sortedValueKeys(raw) {
			m[k] = substituteIteratorValue(raw[k], label, key, item)
		}
		v.Raw = m
		return v
	default:
		return v
	}
}
