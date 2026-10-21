package azure

import (
	"testing"

	"aegis/internal/ir"
)

// Shared test fixtures for the Azure rule pack.

func spanAt(line int) ir.Span {
	return ir.Span{File: "test.tf", StartLine: line, StartCol: 1, EndLine: line, EndCol: 20}
}

func kv(b bool, line int) ir.Value { return ir.Value{Raw: b, Known: true, Span: spanAt(line)} }
func ks(s string, line int) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: spanAt(line)}
}
func ku(line int) ir.Value { return ir.Value{Known: false, Span: spanAt(line)} }

func strList(line int, items ...string) ir.Value {
	vals := make([]ir.Value, len(items))
	for i, s := range items {
		vals[i] = ks(s, line)
	}
	return ir.Value{Raw: vals, Known: true, Span: spanAt(line)}
}

func res(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type:       typ,
		Name:       name,
		Provider:   "azurerm",
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
	if f[0].Evidence.Span.File == "" {
		t.Fatal("evidence must carry a span")
	}
	return f[0]
}

// ---------------------------------------------------------------------------
// Pack registration
// ---------------------------------------------------------------------------

func TestRulesInIDOrder(t *testing.T) {
	rules := Rules()
	want := []string{
		"AEGIS-AZR-001", "AEGIS-AZR-002", "AEGIS-AZR-003",
		"AEGIS-AZR-005",
		"AEGIS-AZURE-006",
		"AEGIS-AZURE-010", "AEGIS-AZURE-011", "AEGIS-AZURE-012", "AEGIS-AZURE-013",
		"AEGIS-AZURE-014", "AEGIS-AZURE-015", "AEGIS-AZURE-016", "AEGIS-AZURE-017",
		"AEGIS-AZURE-018", "AEGIS-AZURE-019", "AEGIS-AZURE-020", "AEGIS-AZURE-021",
		"AEGIS-AZURE-022", "AEGIS-AZURE-023", "AEGIS-AZURE-024",
		"AEGIS-AZURE-026", "AEGIS-AZURE-028", "AEGIS-AZURE-029",
		"AEGIS-AZURE-030", "AEGIS-AZURE-031", "AEGIS-AZURE-032", "AEGIS-AZURE-033",
		"AEGIS-AZURE-034", "AEGIS-AZURE-035", "AEGIS-AZURE-037",
		"AEGIS-AZURE-038", "AEGIS-AZURE-039", "AEGIS-AZURE-040", "AEGIS-AZURE-041",
		"AEGIS-AZURE-042", "AEGIS-AZURE-043", "AEGIS-AZURE-044",
		"AEGIS-AZURE-046", "AEGIS-AZURE-049",
		"AEGIS-AZURE-050", "AEGIS-AZURE-051", "AEGIS-AZURE-052", "AEGIS-AZURE-053",
		"AEGIS-AZURE-054", "AEGIS-AZURE-055", "AEGIS-AZURE-056", "AEGIS-AZURE-057",
		"AEGIS-AZURE-058", "AEGIS-AZURE-059", "AEGIS-AZURE-060", "AEGIS-AZURE-061",
		"AEGIS-AZURE-062", "AEGIS-AZURE-063", "AEGIS-AZURE-064", "AEGIS-AZURE-065",
		"AEGIS-AZURE-066", "AEGIS-AZURE-067", "AEGIS-AZURE-068", "AEGIS-AZURE-069",
		"AEGIS-AZURE-070", "AEGIS-AZURE-071", "AEGIS-AZURE-072", "AEGIS-AZURE-073",
		"AEGIS-AZURE-074", "AEGIS-AZURE-076", "AEGIS-AZURE-077",
		"AEGIS-AZURE-078", "AEGIS-AZURE-079", "AEGIS-AZURE-080", "AEGIS-AZURE-081",
		"AEGIS-AZURE-082", "AEGIS-AZURE-083", "AEGIS-AZURE-084", "AEGIS-AZURE-085",
		"AEGIS-AZURE-086", "AEGIS-AZURE-087", "AEGIS-AZURE-088", "AEGIS-AZURE-089",
		"AEGIS-AZURE-090", "AEGIS-AZURE-091", "AEGIS-AZURE-092", "AEGIS-AZURE-093",
		"AEGIS-AZURE-094", "AEGIS-AZURE-095", "AEGIS-AZURE-096", "AEGIS-AZURE-097",
		"AEGIS-AZURE-098", "AEGIS-AZURE-099", "AEGIS-AZURE-100",
		"AEGIS-AZURE-101", "AEGIS-AZURE-102", "AEGIS-AZURE-103", "AEGIS-AZURE-104",
		"AEGIS-AZURE-105", "AEGIS-AZURE-106", "AEGIS-AZURE-107", "AEGIS-AZURE-108",
		"AEGIS-AZURE-110", "AEGIS-AZURE-111", "AEGIS-AZURE-112",
		"AEGIS-AZURE-113", "AEGIS-AZURE-114", "AEGIS-AZURE-115", "AEGIS-AZURE-116",
		"AEGIS-AZURE-118",
		"AEGIS-AZURE-121", "AEGIS-AZURE-122", "AEGIS-AZURE-124",
		"AEGIS-AZURE-125", "AEGIS-AZURE-127", "AEGIS-AZURE-128",
		"AEGIS-AZURE-129", "AEGIS-AZURE-130", "AEGIS-AZURE-131", "AEGIS-AZURE-132",
		"AEGIS-AZURE-133", "AEGIS-AZURE-134", "AEGIS-AZURE-135", "AEGIS-AZURE-136",
		"AEGIS-AZURE-137", "AEGIS-AZURE-138", "AEGIS-AZURE-139", "AEGIS-AZURE-140",
		"AEGIS-AZURE-141", "AEGIS-AZURE-142", "AEGIS-AZURE-143",
		"AEGIS-AZURE-145", "AEGIS-AZURE-147", "AEGIS-AZURE-148",
		"AEGIS-AZURE-149",
		"AEGIS-AZURE-150", "AEGIS-AZURE-151", "AEGIS-AZURE-152", "AEGIS-AZURE-153",
		"AEGIS-AZURE-154", "AEGIS-AZURE-155", "AEGIS-AZURE-156", "AEGIS-AZURE-157",
		"AEGIS-AZURE-158", "AEGIS-AZURE-159", "AEGIS-AZURE-160", "AEGIS-AZURE-161",
		"AEGIS-AZURE-162", "AEGIS-AZURE-163", "AEGIS-AZURE-164", "AEGIS-AZURE-165",
		"AEGIS-AZURE-166", "AEGIS-AZURE-167", "AEGIS-AZURE-168", "AEGIS-AZURE-169",
		"AEGIS-AZURE-170", "AEGIS-AZURE-171", "AEGIS-AZURE-172", "AEGIS-AZURE-173",
		"AEGIS-AZURE-174", "AEGIS-AZURE-175", "AEGIS-AZURE-176", "AEGIS-AZURE-177",
		"AEGIS-AZURE-179", "AEGIS-AZURE-180", "AEGIS-AZURE-181",
		"AEGIS-AZURE-182", "AEGIS-AZURE-183", "AEGIS-AZURE-184", "AEGIS-AZURE-185",
		"AEGIS-AZURE-186", "AEGIS-AZURE-187", "AEGIS-AZURE-189",
		"AEGIS-AZURE-192",
		"AEGIS-AZURE-194", "AEGIS-AZURE-195", "AEGIS-AZURE-197",
		"AEGIS-AZURE-199", "AEGIS-AZURE-200", "AEGIS-AZURE-201",
		"AEGIS-AZURE-204", "AEGIS-AZURE-205",
		"AEGIS-AZURE-207", "AEGIS-AZURE-208", "AEGIS-AZURE-209",
		"AEGIS-AZURE-210", "AEGIS-AZURE-211", "AEGIS-AZURE-212",
		"AEGIS-AZURE-214", "AEGIS-AZURE-215", "AEGIS-AZURE-216", "AEGIS-AZURE-217",
		"AEGIS-AZURE-218", "AEGIS-AZURE-219", "AEGIS-AZURE-220", "AEGIS-AZURE-221",
		"AEGIS-AZURE-222", "AEGIS-AZURE-223", "AEGIS-AZURE-224",
		"AEGIS-AZURE-226", "AEGIS-AZURE-227", "AEGIS-AZURE-228", "AEGIS-AZURE-229",
		"AEGIS-AZURE-231", "AEGIS-AZURE-232", "AEGIS-AZURE-233",
		"AEGIS-AZURE-235", "AEGIS-AZURE-236", "AEGIS-AZURE-237",
		"AEGIS-AZURE-238", "AEGIS-AZURE-239", "AEGIS-AZURE-240", "AEGIS-AZURE-241",
		"AEGIS-AZURE-242", "AEGIS-AZURE-244",
		"AEGIS-AZURE-246", "AEGIS-AZURE-247", "AEGIS-AZURE-248", "AEGIS-AZURE-249",
		"AEGIS-AZURE-250", "AEGIS-AZURE-251", "AEGIS-AZURE-252", "AEGIS-AZURE-253",
		"AEGIS-AZURE-254", "AEGIS-AZURE-255", "AEGIS-AZURE-256", "AEGIS-AZURE-257",
		"AEGIS-AZURE-258", "AEGIS-AZURE-259", "AEGIS-AZURE-260", "AEGIS-AZURE-261",
		"AEGIS-AZURE-262", "AEGIS-AZURE-263", "AEGIS-AZURE-264", "AEGIS-AZURE-265",
		"AEGIS-AZURE-266", "AEGIS-AZURE-267", "AEGIS-AZURE-268", "AEGIS-AZURE-269",
		"AEGIS-AZURE-270", "AEGIS-AZURE-271", "AEGIS-AZURE-272", "AEGIS-AZURE-273",
		"AEGIS-AZURE-274", "AEGIS-AZURE-275", "AEGIS-AZURE-276", "AEGIS-AZURE-277",
		"AEGIS-AZURE-278", "AEGIS-AZURE-279", "AEGIS-AZURE-280", "AEGIS-AZURE-281",
		"AEGIS-AZURE-282", "AEGIS-AZURE-283", "AEGIS-AZURE-284", "AEGIS-AZURE-285",
		"AEGIS-AZURE-286", "AEGIS-AZURE-287", "AEGIS-AZURE-288", "AEGIS-AZURE-289",
		"AEGIS-AZURE-290", "AEGIS-AZURE-291", "AEGIS-AZURE-292", "AEGIS-AZURE-293",
		"AEGIS-AZURE-294", "AEGIS-AZURE-295", "AEGIS-AZURE-296", "AEGIS-AZURE-297",
		"AEGIS-AZURE-299", "AEGIS-AZURE-300", "AEGIS-AZURE-301",
		"AEGIS-AZURE-302", "AEGIS-AZURE-303", "AEGIS-AZURE-304", "AEGIS-AZURE-305",
		"AEGIS-AZURE-306", "AEGIS-AZURE-307", "AEGIS-AZURE-308", "AEGIS-AZURE-309",
		"AEGIS-AZURE-310", "AEGIS-AZURE-311", "AEGIS-AZURE-313",
		"AEGIS-AZURE-314",
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
// AEGIS-AZR-001
// ---------------------------------------------------------------------------

func TestStoragePublicBlobAccess_Fires(t *testing.T) {
	r := res("azurerm_storage_account", "data", map[string]ir.Value{
		"allow_blob_public_access": kv(true, 3),
	})
	f := mustFinding(t, runRule(storagePublicBlobAccess{}, r), "AEGIS-AZR-001")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestStoragePublicBlobAccess_DisabledOK(t *testing.T) {
	r := res("azurerm_storage_account", "data", map[string]ir.Value{
		"allow_blob_public_access": kv(false, 3),
	})
	if f := runRule(storagePublicBlobAccess{}, r); len(f) != 0 {
		t.Fatalf("disabled access must not fire, got %d", len(f))
	}
}

func TestStoragePublicBlobAccess_UnknownNoFinding(t *testing.T) {
	r := res("azurerm_storage_account", "data", map[string]ir.Value{
		"allow_blob_public_access": ku(3),
	})
	if f := runRule(storagePublicBlobAccess{}, r); len(f) != 0 {
		t.Fatalf("unknown value must not fire, got %d", len(f))
	}
}

func TestStoragePublicBlobAccess_AbsentNoFinding(t *testing.T) {
	r := res("azurerm_storage_account", "data", nil)
	if f := runRule(storagePublicBlobAccess{}, r); len(f) != 0 {
		t.Fatalf("absent attribute must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZR-002
// ---------------------------------------------------------------------------

func TestStorageMinTLS_Fires(t *testing.T) {
	r := res("azurerm_storage_account", "data", map[string]ir.Value{
		"min_tls_version": ks("TLS1_0", 3),
	})
	mustFinding(t, runRule(storageMinTLS{}, r), "AEGIS-AZR-002")
}

func TestStorageMinTLS_TLS12OK(t *testing.T) {
	r := res("azurerm_storage_account", "data", map[string]ir.Value{
		"min_tls_version": ks("TLS1_2", 3),
	})
	if f := runRule(storageMinTLS{}, r); len(f) != 0 {
		t.Fatalf("TLS1_2 must not fire, got %d", len(f))
	}
}

func TestStorageMinTLS_UnknownNoFinding(t *testing.T) {
	r := res("azurerm_storage_account", "data", map[string]ir.Value{
		"min_tls_version": ku(3),
	})
	if f := runRule(storageMinTLS{}, r); len(f) != 0 {
		t.Fatalf("unknown value must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZR-003
// ---------------------------------------------------------------------------

func openNSGRule(sourceAttr string, v ir.Value) ir.Resource {
	return res("azurerm_network_security_rule", "open", map[string]ir.Value{
		"direction": ks("Inbound", 2),
		"access":    ks("Allow", 3),
		sourceAttr:  v,
	})
}

func TestNSGOpenRule_StarFires(t *testing.T) {
	mustFinding(t, runRule(nsgOpenRule{}, openNSGRule("source_address_prefix", ks("*", 4))), "AEGIS-AZR-003")
}

func TestNSGOpenRule_InternetKeywordFires(t *testing.T) {
	mustFinding(t, runRule(nsgOpenRule{}, openNSGRule("source_address_prefix", ks("Internet", 4))), "AEGIS-AZR-003")
}

func TestNSGOpenRule_PrefixListFires(t *testing.T) {
	mustFinding(t, runRule(nsgOpenRule{}, openNSGRule("source_address_prefixes", strList(4, "10.0.0.0/8", "0.0.0.0/0"))), "AEGIS-AZR-003")
}

func TestNSGOpenRule_RestrictedOK(t *testing.T) {
	if f := runRule(nsgOpenRule{}, openNSGRule("source_address_prefix", ks("10.0.0.0/8", 4))); len(f) != 0 {
		t.Fatalf("restricted source must not fire, got %d", len(f))
	}
}

func TestNSGOpenRule_OutboundOK(t *testing.T) {
	r := res("azurerm_network_security_rule", "egress", map[string]ir.Value{
		"direction":             ks("Outbound", 2),
		"access":                ks("Allow", 3),
		"source_address_prefix": ks("*", 4),
	})
	if f := runRule(nsgOpenRule{}, r); len(f) != 0 {
		t.Fatalf("outbound rule must not fire, got %d", len(f))
	}
}

func TestNSGOpenRule_DenyOK(t *testing.T) {
	r := res("azurerm_network_security_rule", "deny", map[string]ir.Value{
		"direction":             ks("Inbound", 2),
		"access":                ks("Deny", 3),
		"source_address_prefix": ks("*", 4),
	})
	if f := runRule(nsgOpenRule{}, r); len(f) != 0 {
		t.Fatalf("deny rule must not fire, got %d", len(f))
	}
}

func TestNSGOpenRule_UnknownSourceNoFinding(t *testing.T) {
	if f := runRule(nsgOpenRule{}, openNSGRule("source_address_prefix", ku(4))); len(f) != 0 {
		t.Fatalf("unknown source must not fire, got %d", len(f))
	}
}

func TestNSGOpenRule_UnknownDirectionNoFinding(t *testing.T) {
	r := res("azurerm_network_security_rule", "open", map[string]ir.Value{
		"direction":             ku(2),
		"access":                ks("Allow", 3),
		"source_address_prefix": ks("*", 4),
	})
	if f := runRule(nsgOpenRule{}, r); len(f) != 0 {
		t.Fatalf("unknown direction must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZR-005
// ---------------------------------------------------------------------------

func TestKeyVaultPurgeProtection_Fires(t *testing.T) {
	r := res("azurerm_key_vault", "secrets", map[string]ir.Value{
		"purge_protection_enabled": kv(false, 3),
	})
	f := mustFinding(t, runRule(keyVaultPurgeProtection{}, r), "AEGIS-AZR-005")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestKeyVaultPurgeProtection_EnabledOK(t *testing.T) {
	r := res("azurerm_key_vault", "secrets", map[string]ir.Value{
		"purge_protection_enabled": kv(true, 3),
	})
	if f := runRule(keyVaultPurgeProtection{}, r); len(f) != 0 {
		t.Fatalf("enabled protection must not fire, got %d", len(f))
	}
}

func TestKeyVaultPurgeProtection_UnknownNoFinding(t *testing.T) {
	r := res("azurerm_key_vault", "secrets", map[string]ir.Value{
		"purge_protection_enabled": ku(3),
	})
	if f := runRule(keyVaultPurgeProtection{}, r); len(f) != 0 {
		t.Fatalf("unknown value must not fire, got %d", len(f))
	}
}

func TestStorageMinTLS_TLS13OK(t *testing.T) {
	r := res("azurerm_storage_account", "data", map[string]ir.Value{
		"min_tls_version": ks("TLS1_3", 3),
	})
	if f := runRule(storageMinTLS{}, r); len(f) != 0 {
		t.Fatalf("TLS1_3 must not fire as 'below TLS 1.2', got %d", len(f))
	}
}
