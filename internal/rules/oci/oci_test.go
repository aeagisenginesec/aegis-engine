package oci

import (
	"testing"

	"aegis/internal/ir"
)

// Shared test fixtures for the OCI rule pack.

func spanAt(line int) ir.Span {
	return ir.Span{File: "test.tf", StartLine: line, StartCol: 1, EndLine: line, EndCol: 20}
}

func kv(b bool, line int) ir.Value { return ir.Value{Raw: b, Known: true, Span: spanAt(line)} }
func ks(s string, line int) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: spanAt(line)}
}
func kn(n float64, line int) ir.Value { return ir.Value{Raw: n, Known: true, Span: spanAt(line)} }
func ku(line int) ir.Value            { return ir.Value{Known: false, Span: spanAt(line)} }

func strList(line int, items ...string) ir.Value {
	vals := make([]ir.Value, len(items))
	for i, s := range items {
		vals[i] = ks(s, line)
	}
	return ir.Value{Raw: vals, Known: true, Span: spanAt(line)}
}

func blk(pairs ...any) map[string]ir.Value {
	m := map[string]ir.Value{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1].(ir.Value)
	}
	return m
}

func blks(line int, maps ...map[string]ir.Value) ir.Value {
	vals := make([]ir.Value, len(maps))
	for i, m := range maps {
		vals[i] = ir.Value{Raw: m, Known: true, Span: spanAt(line)}
	}
	return ir.Value{Raw: vals, Known: true, Span: spanAt(line)}
}

func res(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type:       typ,
		Name:       name,
		Provider:   "oci",
		Attributes: attrs,
		Span:       spanAt(1),
	}
}

func runRule(rule ir.Rule, resources ...ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, r := range resources {
		if rule.AppliesTo(r.Type) {
			out = append(out, rule.Check(r)...)
		}
	}
	return out
}

func mustFinding(t *testing.T, f []ir.Finding, ruleID string) ir.Finding {
	t.Helper()
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(f), f)
	}
	if f[0].RuleID != ruleID {
		t.Fatalf("wrong rule ID: %s", f[0].RuleID)
	}
	if f[0].Resource == "" || f[0].Evidence.Attribute == "" {
		t.Fatal("finding must carry resource and evidence attribute")
	}
	if f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatal("evidence must carry actual and expected")
	}
	return f[0]
}

func mustQuiet(t *testing.T, f []ir.Finding) {
	t.Helper()
	if len(f) != 0 {
		t.Fatalf("expected 0 findings, got %d: %+v", len(f), f)
	}
}

// ---------------------------------------------------------------------------
// Pack registration
// ---------------------------------------------------------------------------

func TestRulesInIDOrder(t *testing.T) {
	rules := Rules()
	want := []string{
		"AEGIS-OCI-001", "AEGIS-OCI-002", "AEGIS-OCI-003", "AEGIS-OCI-004",
		"AEGIS-OCI-005", "AEGIS-OCI-006", "AEGIS-OCI-007", "AEGIS-OCI-008",
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	for i, w := range want {
		if rules[i].ID() != w {
			t.Fatalf("rule %d: want %s, got %s", i, w, rules[i].ID())
		}
		if rules[i].Title() == "" || rules[i].Description() == "" {
			t.Fatalf("rule %s missing title/description", w)
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-001: Object Storage bucket without KMS encryption
// ---------------------------------------------------------------------------

func TestOCI001_AbsentFires(t *testing.T) {
	r := res("oci_objectstorage_bucket", "b", nil)
	f := mustFinding(t, runRule(bucketNoKMS{}, r), "AEGIS-OCI-001")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestOCI001_KeyQuiet(t *testing.T) {
	r := res("oci_objectstorage_bucket", "b", map[string]ir.Value{
		"kms_key_id": ks("ocid1.key.oc1..aaa", 3),
	})
	mustQuiet(t, runRule(bucketNoKMS{}, r))
}

func TestOCI001_UnknownQuiet(t *testing.T) {
	r := res("oci_objectstorage_bucket", "b", map[string]ir.Value{"kms_key_id": ku(3)})
	mustQuiet(t, runRule(bucketNoKMS{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-002: Object Storage bucket with public access
// ---------------------------------------------------------------------------

func TestOCI002_ObjectReadFires(t *testing.T) {
	r := res("oci_objectstorage_bucket", "b", map[string]ir.Value{"access_type": ks("ObjectRead", 3)})
	f := mustFinding(t, runRule(bucketPublicAccess{}, r), "AEGIS-OCI-002")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestOCI002_ObjectReadWithoutListFires(t *testing.T) {
	r := res("oci_objectstorage_bucket", "b", map[string]ir.Value{"access_type": ks("ObjectReadWithoutList", 3)})
	mustFinding(t, runRule(bucketPublicAccess{}, r), "AEGIS-OCI-002")
}

func TestOCI002_NoPublicAccessQuiet(t *testing.T) {
	r := res("oci_objectstorage_bucket", "b", map[string]ir.Value{"access_type": ks("NoPublicAccess", 3)})
	mustQuiet(t, runRule(bucketPublicAccess{}, r))
}

func TestOCI002_AbsentQuiet(t *testing.T) {
	mustQuiet(t, runRule(bucketPublicAccess{}, res("oci_objectstorage_bucket", "b", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-003: VCN security list with open ingress
// ---------------------------------------------------------------------------

func TestOCI003_OpenIngressFires(t *testing.T) {
	r := res("oci_core_security_list", "s", map[string]ir.Value{
		"ingress_security_rules": blks(3,
			blk("source", ks("0.0.0.0/0", 4), "protocol", ks("6", 5)),
			blk("source", ks("10.0.0.0/8", 6), "protocol", ks("6", 7)),
		),
	})
	fs := runRule(seclistOpenIngress{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].RuleID != "AEGIS-OCI-003" {
		t.Fatalf("wrong rule ID: %s", fs[0].RuleID)
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", fs[0].Severity)
	}
}

func TestOCI003_RestrictedQuiet(t *testing.T) {
	r := res("oci_core_security_list", "s", map[string]ir.Value{
		"ingress_security_rules": blks(3, blk("source", ks("10.0.0.0/8", 4))),
	})
	mustQuiet(t, runRule(seclistOpenIngress{}, r))
}

func TestOCI003_AbsentQuiet(t *testing.T) {
	mustQuiet(t, runRule(seclistOpenIngress{}, res("oci_core_security_list", "s", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-004: IAM policy with wildcard manage permissions
// ---------------------------------------------------------------------------

func TestOCI004_ManageAllFires(t *testing.T) {
	r := res("oci_identity_policy", "p", map[string]ir.Value{
		"statements": strList(3,
			"Allow group admins to manage all-resources in tenancy",
			"Allow group readers to inspect instances in compartment dev",
		),
	})
	fs := runRule(policyWildcard{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].RuleID != "AEGIS-OCI-004" {
		t.Fatalf("wrong rule ID: %s", fs[0].RuleID)
	}
	if fs[0].Severity != ir.SeverityCritical {
		t.Fatalf("wrong severity: %s", fs[0].Severity)
	}
}

func TestOCI004_ScopedQuiet(t *testing.T) {
	r := res("oci_identity_policy", "p", map[string]ir.Value{
		"statements": strList(3, "Allow group devs to manage instances in compartment prod"),
	})
	mustQuiet(t, runRule(policyWildcard{}, r))
}

func TestOCI004_AbsentQuiet(t *testing.T) {
	mustQuiet(t, runRule(policyWildcard{}, res("oci_identity_policy", "p", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-005: Block volume without KMS encryption
// ---------------------------------------------------------------------------

func TestOCI005_AbsentFires(t *testing.T) {
	r := res("oci_core_volume", "v", nil)
	f := mustFinding(t, runRule(volumeNoKMS{}, r), "AEGIS-OCI-005")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestOCI005_KeyQuiet(t *testing.T) {
	r := res("oci_core_volume", "v", map[string]ir.Value{"kms_key_id": ks("ocid1.key.oc1..aaa", 3)})
	mustQuiet(t, runRule(volumeNoKMS{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-006: Autonomous Database without customer-managed encryption
// ---------------------------------------------------------------------------

func TestOCI006_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(adbNoKMS{}, res("oci_database_autonomous_database", "db", nil)), "AEGIS-OCI-006")
}

func TestOCI006_KeyQuiet(t *testing.T) {
	r := res("oci_database_autonomous_database", "db", map[string]ir.Value{
		"kms_key_id": ks("ocid1.key.oc1..aaa", 3),
	})
	mustQuiet(t, runRule(adbNoKMS{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-007: Cloud Guard not enabled
// ---------------------------------------------------------------------------

func TestOCI007_AbsentFires(t *testing.T) {
	r := res("oci_cloud_guard_cloud_guard_configuration", "cg", nil)
	f := mustFinding(t, runRule(cloudGuardOff{}, r), "AEGIS-OCI-007")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestOCI007_DisabledFires(t *testing.T) {
	r := res("oci_cloud_guard_cloud_guard_configuration", "cg", map[string]ir.Value{
		"status": ks("DISABLED", 3),
	})
	mustFinding(t, runRule(cloudGuardOff{}, r), "AEGIS-OCI-007")
}

func TestOCI007_EnabledQuiet(t *testing.T) {
	r := res("oci_cloud_guard_cloud_guard_configuration", "cg", map[string]ir.Value{
		"status": ks("ENABLED", 3),
	})
	mustQuiet(t, runRule(cloudGuardOff{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-OCI-008: Logging log with short retention
// ---------------------------------------------------------------------------

func TestOCI008_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(logShortRetention{}, res("oci_logging_log", "l", nil)), "AEGIS-OCI-008")
}

func TestOCI008_ShortFires(t *testing.T) {
	r := res("oci_logging_log", "l", map[string]ir.Value{"retention_period": kn(30, 3)})
	mustFinding(t, runRule(logShortRetention{}, r), "AEGIS-OCI-008")
}

func TestOCI008_LongQuiet(t *testing.T) {
	r := res("oci_logging_log", "l", map[string]ir.Value{"retention_period": kn(365, 3)})
	mustQuiet(t, runRule(logShortRetention{}, r))
}
