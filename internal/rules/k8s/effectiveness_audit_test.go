package k8s

import (
	"testing"

	"aegis/internal/ir"
)

// Effectiveness audit (ITEM 3): generated replay tests. Each test
// replays a black-box probe-discovered firing input (positive) and
// quiet input (negative), plus an all-unknown input that must stay
// quiet. The witnesses were verified by executing the rule; see
// docs/audit/14_RULE_EFFECTIVENESS.md.

// ---- shared replay helpers (ea- prefix; local to this file) ----

func eaB(b bool) ir.Value { return ir.Value{Raw: b, Known: true} }

func eaS(s string) ir.Value { return ir.Value{Raw: s, Known: true} }

func eaN(n float64) ir.Value { return ir.Value{Raw: n, Known: true} }

func eaL(items ...ir.Value) ir.Value { return ir.Value{Raw: items, Known: true} }

func eaM(pairs ...any) ir.Value {
	m := map[string]ir.Value{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1].(ir.Value)
	}
	return ir.Value{Raw: m, Known: true}
}

func eaU() ir.Value { return ir.Value{Known: false} }

func eaR(ref string) ir.Value { return ir.Value{Known: false, Ref: ref} }

func eaRes(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{Type: typ, Name: name, Provider: "audit", Attributes: attrs}
}

// eaRun evaluates rule the way the engine does: CheckAll for
// cross-resource rules, Check per applicable resource otherwise.
func eaRun(rule ir.Rule, resources ...ir.Resource) []ir.Finding {
	var out []ir.Finding
	if cr, ok := rule.(ir.CrossResourceRule); ok {
		out = append(out, cr.CheckAll(resources)...)
	} else {
		for _, r := range resources {
			if rule.AppliesTo(r.Type) {
				out = append(out, rule.Check(r)...)
			}
		}
	}
	var filtered []ir.Finding
	for _, f := range out {
		if f.RuleID == rule.ID() {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// eaRuleFor looks a rule up by ID in this pack's registry.
func eaRuleFor(t *testing.T, id string) ir.Rule {
	t.Helper()
	for _, r := range Rules() {
		if r.ID() == id {
			return r
		}
	}
	t.Fatalf("rule %s not found in pack registry", id)
	return nil
}
func TestEffectivenessReplay_K8S_001(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-K8S-001")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("k8s_pod", "probe", map[string]ir.Value{
			"spec": eaM("allowPrivilegeEscalation", eaB(true), "containers", eaL(eaM("allowPrivilegeEscalation", eaB(true), "containers", eaS("public"), "initContainers", eaS("public"), "jobTemplate", eaS("public"), "k8s_", eaS("public"), "name", eaS("my_password"), "privileged", eaB(true), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0), "securityContext", eaM("allowPrivilegeEscalation", eaB(true), "privileged", eaB(true), "readOnlyRootFilesystem", eaB(false), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0)), "spec", eaS("public"), "template", eaS("public"))), "jobTemplate", eaS("public"), "k8s_", eaS("public"), "name", eaS("my_password"), "privileged", eaB(true), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0), "securityContext", eaM("allowPrivilegeEscalation", eaB(true), "privileged", eaB(true), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-K8S-001: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-K8S-001: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-K8S-001: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("k8s_pod", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-K8S-001: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("k8s_pod", "probe", map[string]ir.Value{
		"allowPrivilegeEscalation": eaU(),
		"containers":               eaU(),
		"initContainers":           eaU(),
		"jobTemplate":              eaU(),
		"k8s_":                     eaU(),
		"name":                     eaU(),
		"privileged":               eaU(),
		"runAsNonRoot":             eaU(),
		"runAsUser":                eaU(),
		"securityContext":          eaU(),
		"spec":                     eaU(),
		"template":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-K8S-001: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_K8S_002(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-K8S-002")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("k8s_pod", "probe", map[string]ir.Value{
			"spec": eaM("allowPrivilegeEscalation", eaB(true), "containers", eaL(eaM("allowPrivilegeEscalation", eaB(true), "containers", eaS("public"), "initContainers", eaS("public"), "jobTemplate", eaS("public"), "k8s_", eaS("public"), "name", eaS("my_password"), "privileged", eaB(true), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0), "securityContext", eaM("allowPrivilegeEscalation", eaB(true), "privileged", eaB(true), "readOnlyRootFilesystem", eaB(false), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0)), "spec", eaS("public"), "template", eaS("public"))), "jobTemplate", eaS("public"), "k8s_", eaS("public"), "name", eaS("my_password"), "privileged", eaB(true), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0), "securityContext", eaM("allowPrivilegeEscalation", eaB(true), "privileged", eaB(true), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-K8S-002: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-K8S-002: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-K8S-002: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("k8s_pod", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-K8S-002: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("k8s_pod", "probe", map[string]ir.Value{
		"allowPrivilegeEscalation": eaU(),
		"containers":               eaU(),
		"initContainers":           eaU(),
		"jobTemplate":              eaU(),
		"k8s_":                     eaU(),
		"name":                     eaU(),
		"privileged":               eaU(),
		"runAsNonRoot":             eaU(),
		"runAsUser":                eaU(),
		"securityContext":          eaU(),
		"spec":                     eaU(),
		"template":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-K8S-002: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_K8S_003(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-K8S-003")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("k8s_pod", "probe", map[string]ir.Value{
			"spec": eaM("allowPrivilegeEscalation", eaB(true), "containers", eaL(eaM("allowPrivilegeEscalation", eaB(true), "containers", eaS("public"), "initContainers", eaS("public"), "jobTemplate", eaS("public"), "k8s_", eaS("public"), "name", eaS("my_password"), "privileged", eaB(true), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0), "securityContext", eaM("allowPrivilegeEscalation", eaB(true), "privileged", eaB(true), "readOnlyRootFilesystem", eaB(false), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0)), "spec", eaS("public"), "template", eaS("public"))), "jobTemplate", eaS("public"), "k8s_", eaS("public"), "name", eaS("my_password"), "privileged", eaB(true), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0), "securityContext", eaM("allowPrivilegeEscalation", eaB(true), "privileged", eaB(true), "runAsNonRoot", eaB(false), "runAsUser", eaN(0.0))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-K8S-003: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-K8S-003: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-K8S-003: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("k8s_pod", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-K8S-003: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("k8s_pod", "probe", map[string]ir.Value{
		"allowPrivilegeEscalation": eaU(),
		"containers":               eaU(),
		"initContainers":           eaU(),
		"jobTemplate":              eaU(),
		"k8s_":                     eaU(),
		"name":                     eaU(),
		"privileged":               eaU(),
		"runAsNonRoot":             eaU(),
		"runAsUser":                eaU(),
		"securityContext":          eaU(),
		"spec":                     eaU(),
		"template":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-K8S-003: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
