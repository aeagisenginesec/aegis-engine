// Package azure implements the Aegis Azure security rule pack.
//
// Unknown-value contract (hard rule): an attribute that is present but
// unresolved (Value.Known == false, or a shape we cannot interpret) yields
// NO finding. An attribute that is ABSENT is evaluated against the insecure
// default documented per rule; for this starter pack, absent attributes
// yield no finding unless the rule explicitly documents otherwise.
// Rules never panic on unexpected shapes.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// PackName identifies the Azure rule pack.
const PackName = "aegis-azure"

// Rules returns every rule in the Azure pack, in ID order.
func Rules() []ir.Rule {
	rules := []ir.Rule{
		storagePublicBlobAccess{}, // AEGIS-AZR-001
		storageMinTLS{},           // AEGIS-AZR-002
		nsgOpenRule{},             // AEGIS-AZR-003
		sqlPublicAccess{},         // AEGIS-AZR-004
		keyVaultPurgeProtection{}, // AEGIS-AZR-005
	}
	rules = append(rules, Azure2Rules()...)  // AEGIS-AZURE-006..025
	rules = append(rules, Azure3Rules()...)  // AEGIS-AZURE-026..043
	rules = append(rules, Azure4Rules()...)  // AEGIS-AZURE-044..060
	rules = append(rules, Azure5Rules()...)  // AEGIS-AZURE-061..080
	rules = append(rules, Azure6Rules()...)  // AEGIS-AZURE-081..100
	rules = append(rules, Azure7Rules()...)  // AEGIS-AZURE-101..108
	rules = append(rules, Azure8Rules()...)  // AEGIS-AZURE-109..118
	rules = append(rules, Azure9Rules()...)  // AEGIS-AZURE-119..126
	rules = append(rules, Azure10Rules()...) // AEGIS-AZURE-127..136
	rules = append(rules, Azure11Rules()...) // AEGIS-AZURE-137..143
	rules = append(rules, Azure12Rules()...) // AEGIS-AZURE-144..149
	return rules
}

// getBool classifies a boolean attribute into a tri-state.
// present=false means the attribute key is absent.
// known=false means present but unresolved or not a bool — undecidable.
func getBool(r ir.Resource, name string) (val bool, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	b, kok := v.AsBool()
	return b, v.Span, true, kok
}

// getString classifies a string attribute into a tri-state.
func getString(r ir.Resource, name string) (val string, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := v.AsString()
	return s, v.Span, true, kok
}

// getStringList extracts a known list of strings; ok=false when the list
// is absent, unresolved, or contains non-string elements.
func getStringList(r ir.Resource, name string) ([]string, ir.Span, bool) {
	v, ok := r.Attributes[name]
	if !ok || !v.Known {
		return nil, ir.Span{}, false
	}
	l, ok := v.AsList()
	if !ok {
		return nil, v.Span, false
	}
	out := make([]string, 0, len(l))
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return nil, v.Span, false
		}
		out = append(out, s)
	}
	return out, v.Span, true
}

// evidenceSpan prefers the attribute span, falling back to the resource span.
func evidenceSpan(attrSpan, resSpan ir.Span) ir.Span {
	if attrSpan.File != "" {
		return attrSpan
	}
	return resSpan
}

// mkFinding builds a finding with evidence.
func mkFinding(rule ir.Rule, r ir.Resource, attr string, span ir.Span, actual, expected string) ir.Finding {
	return ir.Finding{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZR-001: Storage account allows public blob access
// ---------------------------------------------------------------------------

type storagePublicBlobAccess struct{}

func (storagePublicBlobAccess) ID() string { return "AEGIS-AZR-001" }
func (storagePublicBlobAccess) Title() string {
	return "Storage account allows public blob access"
}
func (storagePublicBlobAccess) Description() string {
	return "allow_blob_public_access exposes blob data to anonymous requests. " +
		"It should be disabled unless public content delivery is intended."
}
func (storagePublicBlobAccess) Severity() ir.Severity { return ir.SeverityHigh }

func (storagePublicBlobAccess) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storagePublicBlobAccess) Check(r ir.Resource) []ir.Finding {
	allow, span, present, known := getBool(r, "allow_blob_public_access")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !allow {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "allow_blob_public_access", span,
		"true", "allow_blob_public_access = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZR-002: Storage account below TLS 1.2
// ---------------------------------------------------------------------------

type storageMinTLS struct{}

func (storageMinTLS) ID() string { return "AEGIS-AZR-002" }
func (storageMinTLS) Title() string {
	return "Storage account below TLS 1.2"
}
func (storageMinTLS) Description() string {
	return "Storage accounts should enforce TLS 1.2 as the minimum version " +
		"to protect data in transit against protocol downgrade attacks."
}
func (storageMinTLS) Severity() ir.Severity { return ir.SeverityMedium }

func (storageMinTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageMinTLS) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "min_tls_version")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if strings.EqualFold(strings.TrimSpace(ver), "TLS1_2") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "min_tls_version", span,
		ver, "min_tls_version = \"TLS1_2\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZR-003: NSG rule open to the internet
// ---------------------------------------------------------------------------

type nsgOpenRule struct{}

func (nsgOpenRule) ID() string { return "AEGIS-AZR-003" }
func (nsgOpenRule) Title() string {
	return "NSG rule open to the internet"
}
func (nsgOpenRule) Description() string {
	return "An inbound Allow network security rule with a source of *, " +
		"0.0.0.0/0, or Internet exposes the protected resource to the world."
}
func (nsgOpenRule) Severity() ir.Severity { return ir.SeverityHigh }

func (nsgOpenRule) AppliesTo(resType string) bool {
	return resType == "azurerm_network_security_rule"
}

// openSourcePrefixes are source values that mean "the internet".
var openSourcePrefixes = map[string]bool{
	"*":         true,
	"0.0.0.0/0": true,
	"internet":  true,
}

func isOpenSource(s string) bool {
	return openSourcePrefixes[strings.ToLower(strings.TrimSpace(s))]
}

func (s nsgOpenRule) Check(r ir.Resource) []ir.Finding {
	dir, _, dpresent, dknown := getString(r, "direction")
	access, _, apresent, aknown := getString(r, "access")
	if !dpresent || !dknown || !apresent || !aknown {
		return nil // direction/access unresolved: cannot decide
	}
	if !strings.EqualFold(strings.TrimSpace(dir), "Inbound") {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(access), "Allow") {
		return nil
	}
	// Single source prefix.
	if pfx, span, present, known := getString(r, "source_address_prefix"); present {
		if !known {
			return nil // unresolved: cannot decide
		}
		if isOpenSource(pfx) {
			return []ir.Finding{mkFinding(s, r, "source_address_prefix", span,
				pfx, "restricted source address prefix")}
		}
		return nil
	}
	// Multiple source prefixes.
	if pfxs, span, ok := getStringList(r, "source_address_prefixes"); ok {
		for _, pfx := range pfxs {
			if isOpenSource(pfx) {
				return []ir.Finding{mkFinding(s, r, "source_address_prefixes", span,
					pfx, "restricted source address prefixes")}
			}
		}
		return nil
	}
	// Source absent or unresolved: cannot decide.
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZR-004: SQL server public network access
// ---------------------------------------------------------------------------

type sqlPublicAccess struct{}

func (sqlPublicAccess) ID() string { return "AEGIS-AZR-004" }
func (sqlPublicAccess) Title() string {
	return "SQL server allows public network access"
}
func (sqlPublicAccess) Description() string {
	return "azurerm_mssql_server with public_network_access_enabled exposes " +
		"the database endpoint to the internet. It should be disabled in favor " +
		"of private endpoints."
}
func (sqlPublicAccess) Severity() ir.Severity { return ir.SeverityHigh }

func (sqlPublicAccess) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server"
}

func (s sqlPublicAccess) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "public_network_access_enabled")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !pub {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "public_network_access_enabled", span,
		"true", "public_network_access_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZR-005: Key Vault without purge protection
// ---------------------------------------------------------------------------

type keyVaultPurgeProtection struct{}

func (keyVaultPurgeProtection) ID() string { return "AEGIS-AZR-005" }
func (keyVaultPurgeProtection) Title() string {
	return "Key Vault without purge protection"
}
func (keyVaultPurgeProtection) Description() string {
	return "purge_protection_enabled guards against permanent, irrecoverable " +
		"deletion of keys and secrets. It should be enabled on every vault."
}
func (keyVaultPurgeProtection) Severity() ir.Severity { return ir.SeverityMedium }

func (keyVaultPurgeProtection) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault"
}

func (s keyVaultPurgeProtection) Check(r ir.Resource) []ir.Finding {
	prot, span, present, known := getBool(r, "purge_protection_enabled")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if prot {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "purge_protection_enabled", span,
		"false", "purge_protection_enabled = true")}
}
