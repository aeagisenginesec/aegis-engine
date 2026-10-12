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
		"AEGIS-AZR-004", "AEGIS-AZR-005",
		"AEGIS-AZURE-006", "AEGIS-AZURE-007", "AEGIS-AZURE-008", "AEGIS-AZURE-009",
		"AEGIS-AZURE-010", "AEGIS-AZURE-011", "AEGIS-AZURE-012", "AEGIS-AZURE-013",
		"AEGIS-AZURE-014", "AEGIS-AZURE-015", "AEGIS-AZURE-016", "AEGIS-AZURE-017",
		"AEGIS-AZURE-018", "AEGIS-AZURE-019", "AEGIS-AZURE-020", "AEGIS-AZURE-021",
		"AEGIS-AZURE-022", "AEGIS-AZURE-023", "AEGIS-AZURE-024", "AEGIS-AZURE-025",
		"AEGIS-AZURE-026", "AEGIS-AZURE-027", "AEGIS-AZURE-028", "AEGIS-AZURE-029",
		"AEGIS-AZURE-030", "AEGIS-AZURE-031", "AEGIS-AZURE-032", "AEGIS-AZURE-033",
		"AEGIS-AZURE-034", "AEGIS-AZURE-035", "AEGIS-AZURE-036", "AEGIS-AZURE-037",
		"AEGIS-AZURE-038", "AEGIS-AZURE-039", "AEGIS-AZURE-040", "AEGIS-AZURE-041",
		"AEGIS-AZURE-042", "AEGIS-AZURE-043", "AEGIS-AZURE-044", "AEGIS-AZURE-045",
		"AEGIS-AZURE-046", "AEGIS-AZURE-047", "AEGIS-AZURE-048", "AEGIS-AZURE-049",
		"AEGIS-AZURE-050", "AEGIS-AZURE-051", "AEGIS-AZURE-052", "AEGIS-AZURE-053",
		"AEGIS-AZURE-054", "AEGIS-AZURE-055", "AEGIS-AZURE-056", "AEGIS-AZURE-057",
		"AEGIS-AZURE-058", "AEGIS-AZURE-059", "AEGIS-AZURE-060", "AEGIS-AZURE-061",
		"AEGIS-AZURE-062", "AEGIS-AZURE-063", "AEGIS-AZURE-064", "AEGIS-AZURE-065",
		"AEGIS-AZURE-066", "AEGIS-AZURE-067", "AEGIS-AZURE-068", "AEGIS-AZURE-069",
		"AEGIS-AZURE-070", "AEGIS-AZURE-071", "AEGIS-AZURE-072", "AEGIS-AZURE-073",
		"AEGIS-AZURE-074", "AEGIS-AZURE-075", "AEGIS-AZURE-076", "AEGIS-AZURE-077",
		"AEGIS-AZURE-078", "AEGIS-AZURE-079", "AEGIS-AZURE-080", "AEGIS-AZURE-081",
		"AEGIS-AZURE-082", "AEGIS-AZURE-083", "AEGIS-AZURE-084", "AEGIS-AZURE-085",
		"AEGIS-AZURE-086", "AEGIS-AZURE-087", "AEGIS-AZURE-088", "AEGIS-AZURE-089",
		"AEGIS-AZURE-090", "AEGIS-AZURE-091", "AEGIS-AZURE-092", "AEGIS-AZURE-093",
		"AEGIS-AZURE-094", "AEGIS-AZURE-095", "AEGIS-AZURE-096", "AEGIS-AZURE-097",
		"AEGIS-AZURE-098", "AEGIS-AZURE-099", "AEGIS-AZURE-100",
		"AEGIS-AZURE-101", "AEGIS-AZURE-102", "AEGIS-AZURE-103", "AEGIS-AZURE-104",
		"AEGIS-AZURE-105", "AEGIS-AZURE-106", "AEGIS-AZURE-107", "AEGIS-AZURE-108",
		"AEGIS-AZURE-109", "AEGIS-AZURE-110", "AEGIS-AZURE-111", "AEGIS-AZURE-112",
		"AEGIS-AZURE-113", "AEGIS-AZURE-114", "AEGIS-AZURE-115", "AEGIS-AZURE-116",
		"AEGIS-AZURE-117", "AEGIS-AZURE-118", "AEGIS-AZURE-119", "AEGIS-AZURE-120",
		"AEGIS-AZURE-121", "AEGIS-AZURE-122", "AEGIS-AZURE-123", "AEGIS-AZURE-124",
		"AEGIS-AZURE-125", "AEGIS-AZURE-126", "AEGIS-AZURE-127", "AEGIS-AZURE-128",
		"AEGIS-AZURE-129", "AEGIS-AZURE-130", "AEGIS-AZURE-131", "AEGIS-AZURE-132",
		"AEGIS-AZURE-133", "AEGIS-AZURE-134", "AEGIS-AZURE-135", "AEGIS-AZURE-136",
		"AEGIS-AZURE-137", "AEGIS-AZURE-138", "AEGIS-AZURE-139", "AEGIS-AZURE-140",
		"AEGIS-AZURE-141", "AEGIS-AZURE-142", "AEGIS-AZURE-143", "AEGIS-AZURE-144",
		"AEGIS-AZURE-145", "AEGIS-AZURE-146", "AEGIS-AZURE-147", "AEGIS-AZURE-148",
		"AEGIS-AZURE-149",
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
// AEGIS-AZR-004
// ---------------------------------------------------------------------------

func TestSQLPublicAccess_Fires(t *testing.T) {
	r := res("azurerm_mssql_server", "db", map[string]ir.Value{
		"public_network_access_enabled": kv(true, 3),
	})
	f := mustFinding(t, runRule(sqlPublicAccess{}, r), "AEGIS-AZR-004")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestSQLPublicAccess_DisabledOK(t *testing.T) {
	r := res("azurerm_mssql_server", "db", map[string]ir.Value{
		"public_network_access_enabled": kv(false, 3),
	})
	if f := runRule(sqlPublicAccess{}, r); len(f) != 0 {
		t.Fatalf("disabled access must not fire, got %d", len(f))
	}
}

func TestSQLPublicAccess_UnknownNoFinding(t *testing.T) {
	r := res("azurerm_mssql_server", "db", map[string]ir.Value{
		"public_network_access_enabled": ku(3),
	})
	if f := runRule(sqlPublicAccess{}, r); len(f) != 0 {
		t.Fatalf("unknown value must not fire, got %d", len(f))
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
	if f.Severity != ir.SeverityMedium {
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
