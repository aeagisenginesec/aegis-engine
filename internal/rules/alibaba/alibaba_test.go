package alibaba

import (
	"testing"

	"aegis/internal/ir"
)

// Shared test fixtures for the Alibaba Cloud rule pack.

func spanAt(line int) ir.Span {
	return ir.Span{File: "test.tf", StartLine: line, StartCol: 1, EndLine: line, EndCol: 20}
}

func kv(b bool, line int) ir.Value { return ir.Value{Raw: b, Known: true, Span: spanAt(line)} }
func ks(s string, line int) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: spanAt(line)}
}
func kn(n float64, line int) ir.Value { return ir.Value{Raw: n, Known: true, Span: spanAt(line)} }
func ku(line int) ir.Value            { return ir.Value{Known: false, Span: spanAt(line)} }

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
		Provider:   "alicloud",
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
		"AEGIS-ALI-001", "AEGIS-ALI-002", "AEGIS-ALI-003", "AEGIS-ALI-004",
		"AEGIS-ALI-005", "AEGIS-ALI-006", "AEGIS-ALI-007", "AEGIS-ALI-008",
		"AEGIS-ALI-009", "AEGIS-ALI-010", "AEGIS-ALI-011", "AEGIS-ALI-012",
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
// AEGIS-ALI-001: OSS bucket without server-side encryption
// ---------------------------------------------------------------------------

func TestALI001_AbsentFires(t *testing.T) {
	r := res("alicloud_oss_bucket", "data", nil)
	f := mustFinding(t, runRule(ossNoEncryption{}, r), "AEGIS-ALI-001")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestALI001_BlockQuiet(t *testing.T) {
	r := res("alicloud_oss_bucket", "data", map[string]ir.Value{
		"server_side_encryption_rule": blks(3, blk("sse_algorithm", ks("KMS", 4))),
	})
	mustQuiet(t, runRule(ossNoEncryption{}, r))
}

func TestALI001_UnknownQuiet(t *testing.T) {
	r := res("alicloud_oss_bucket", "data", map[string]ir.Value{
		"server_side_encryption_rule": ku(3),
	})
	mustQuiet(t, runRule(ossNoEncryption{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-002: OSS bucket publicly accessible
// ---------------------------------------------------------------------------

func TestALI002_PublicReadFires(t *testing.T) {
	r := res("alicloud_oss_bucket", "pub", map[string]ir.Value{"acl": ks("public-read", 3)})
	f := mustFinding(t, runRule(ossPublicACL{}, r), "AEGIS-ALI-002")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestALI002_PublicReadWriteFires(t *testing.T) {
	r := res("alicloud_oss_bucket", "pub", map[string]ir.Value{"acl": ks("public-read-write", 3)})
	mustFinding(t, runRule(ossPublicACL{}, r), "AEGIS-ALI-002")
}

func TestALI002_PrivateQuiet(t *testing.T) {
	r := res("alicloud_oss_bucket", "priv", map[string]ir.Value{"acl": ks("private", 3)})
	mustQuiet(t, runRule(ossPublicACL{}, r))
}

func TestALI002_AbsentQuiet(t *testing.T) {
	// default acl is private
	mustQuiet(t, runRule(ossPublicACL{}, res("alicloud_oss_bucket", "d", nil)))
}

func TestALI002_PublicAccessBlockDisabledFires(t *testing.T) {
	r := res("alicloud_oss_bucket_public_access_block", "b", map[string]ir.Value{
		"block_public_acls": kv(false, 3),
	})
	mustFinding(t, runRule(ossPublicACL{}, r), "AEGIS-ALI-002")
}

func TestALI002_PublicAccessBlockEnabledQuiet(t *testing.T) {
	r := res("alicloud_oss_bucket_public_access_block", "b", map[string]ir.Value{
		"block_public_acls": kv(true, 3),
	})
	mustQuiet(t, runRule(ossPublicACL{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-003: OSS bucket without versioning
// ---------------------------------------------------------------------------

func TestALI003_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(ossNoVersioning{}, res("alicloud_oss_bucket", "d", nil)), "AEGIS-ALI-003")
}

func TestALI003_SuspendedFires(t *testing.T) {
	r := res("alicloud_oss_bucket", "d", map[string]ir.Value{
		"versioning": blks(3, blk("status", ks("Suspended", 4))),
	})
	mustFinding(t, runRule(ossNoVersioning{}, r), "AEGIS-ALI-003")
}

func TestALI003_EnabledQuiet(t *testing.T) {
	r := res("alicloud_oss_bucket", "d", map[string]ir.Value{
		"versioning": blks(3, blk("status", ks("Enabled", 4))),
	})
	mustQuiet(t, runRule(ossNoVersioning{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-004: OSS bucket without access logging
// ---------------------------------------------------------------------------

func TestALI004_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(ossNoLogging{}, res("alicloud_oss_bucket", "d", nil)), "AEGIS-ALI-004")
}

func TestALI004_BlockQuiet(t *testing.T) {
	r := res("alicloud_oss_bucket", "d", map[string]ir.Value{
		"logging": blks(3, blk("target_bucket", ks("logs", 4))),
	})
	mustQuiet(t, runRule(ossNoLogging{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-005: RAM account password policy too weak
// ---------------------------------------------------------------------------

func strongPolicy() map[string]ir.Value {
	return map[string]ir.Value{
		"minimum_password_length":      kn(14, 2),
		"require_lowercase_characters": kv(true, 3),
		"require_uppercase_characters": kv(true, 4),
		"require_numbers":              kv(true, 5),
		"require_symbols":              kv(true, 6),
		"hard_expiry":                  kv(true, 7),
		"max_password_age":             kn(90, 8),
	}
}

func TestALI005_AbsentFires(t *testing.T) {
	r := res("alicloud_ram_account_password_policy", "p", nil)
	f := mustFinding(t, runRule(ramWeakPasswordPolicy{}, r), "AEGIS-ALI-005")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestALI005_ShortLengthFires(t *testing.T) {
	attrs := strongPolicy()
	attrs["minimum_password_length"] = kn(8, 2)
	r := res("alicloud_ram_account_password_policy", "p", attrs)
	mustFinding(t, runRule(ramWeakPasswordPolicy{}, r), "AEGIS-ALI-005")
}

func TestALI005_NoSymbolsFires(t *testing.T) {
	attrs := strongPolicy()
	attrs["require_symbols"] = kv(false, 6)
	r := res("alicloud_ram_account_password_policy", "p", attrs)
	mustFinding(t, runRule(ramWeakPasswordPolicy{}, r), "AEGIS-ALI-005")
}

func TestALI005_StrongQuiet(t *testing.T) {
	r := res("alicloud_ram_account_password_policy", "p", strongPolicy())
	mustQuiet(t, runRule(ramWeakPasswordPolicy{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-006: RAM login profile without MFA bind requirement
// ---------------------------------------------------------------------------

func TestALI006_AbsentFires(t *testing.T) {
	r := res("alicloud_ram_login_profile", "p", nil)
	f := mustFinding(t, runRule(ramLoginNoMFA{}, r), "AEGIS-ALI-006")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestALI006_FalseFires(t *testing.T) {
	r := res("alicloud_ram_login_profile", "p", map[string]ir.Value{"mfa_bind_required": kv(false, 3)})
	mustFinding(t, runRule(ramLoginNoMFA{}, r), "AEGIS-ALI-006")
}

func TestALI006_TrueQuiet(t *testing.T) {
	r := res("alicloud_ram_login_profile", "p", map[string]ir.Value{"mfa_bind_required": kv(true, 3)})
	mustQuiet(t, runRule(ramLoginNoMFA{}, r))
}

func TestALI006_UnknownQuiet(t *testing.T) {
	r := res("alicloud_ram_login_profile", "p", map[string]ir.Value{"mfa_bind_required": ku(3)})
	mustQuiet(t, runRule(ramLoginNoMFA{}, r))
}
