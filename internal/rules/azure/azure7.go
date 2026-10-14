// Package azure — MSSQL hardening rules, second tranche (AEGIS-AZURE-101..108).
//
// These close Checkov parity gaps on TerraGoat around azurerm_mssql_server:
// extended auditing via the standalone
// azurerm_mssql_server_extended_auditing_policy resource, security alert
// policy coverage, TLS minimum, public network access default, Azure AD
// administration and private endpoints — the latter three as cross-resource
// correlations because the related configuration lives in separate
// resources (azurerm_mssql_server_azuread_administrator,
// azurerm_private_endpoint).
package azure

import (
	"sort"
	"strings"

	"aegis/internal/ir"
)

// Azure7Rules returns MSSQL hardening rules in ID order.
func Azure7Rules() []ir.Rule {
	return []ir.Rule{
		mssqlNoExtAuditPolicy{},    // AEGIS-AZURE-101
		mssqlAuditRetentionLow{},   // AEGIS-AZURE-102
		mssqlThreatDetectPartial{}, // AEGIS-AZURE-103
		mssqlAlertEmailDisabled{},  // AEGIS-AZURE-104
		mssqlTLSBelow12{},          // AEGIS-AZURE-105
		mssqlPublicAccessDefault{}, // AEGIS-AZURE-106
		mssqlNoADAdminResource{},   // AEGIS-AZURE-107
		mssqlNoPrivateEndpoint{},   // AEGIS-AZURE-108
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-101: MSSQL server without auditing enabled
// ---------------------------------------------------------------------------

type mssqlNoExtAuditPolicy struct{}

func (mssqlNoExtAuditPolicy) ID() string { return "AEGIS-AZURE-101" }
func (mssqlNoExtAuditPolicy) Title() string {
	return "MSSQL server without auditing enabled"
}
func (mssqlNoExtAuditPolicy) Description() string {
	return "azurerm_mssql_server with no azurerm_mssql_server_extended_auditing_policy " +
		"referencing it loses the database activity audit trail. Attach an " +
		"extended auditing policy with a storage endpoint. The legacy " +
		"azurerm_sql_server type is covered the same way via its inline " +
		"extended_auditing_policy block (it has no standalone policy resource)."
}
func (mssqlNoExtAuditPolicy) Severity() ir.Severity { return ir.SeverityMedium }

func (mssqlNoExtAuditPolicy) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server" || resType == "azurerm_sql_server"
}

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (mssqlNoExtAuditPolicy) Check(ir.Resource) []ir.Finding { return nil }

func (mssqlNoExtAuditPolicy) CheckAll(resources []ir.Resource) []ir.Finding {
	s := mssqlNoExtAuditPolicy{}
	audited := map[string]bool{}
	for _, r := range resources {
		if r.Type != "azurerm_mssql_server_extended_auditing_policy" {
			continue
		}
		for _, addr := range refAddrs(r) {
			audited[addr] = true
		}
	}
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	var out []ir.Finding
	for _, r := range sorted {
		if r.Type != "azurerm_mssql_server" && r.Type != "azurerm_sql_server" {
			continue
		}
		// Inline block also counts as auditing.
		if _, _, present, _ := getBlocks(r, "extended_auditing_policy"); present {
			continue
		}
		if audited[r.Address()] {
			continue
		}
		out = append(out, mkFinding(s, r, "extended_auditing_policy",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"azurerm_mssql_server_extended_auditing_policy with server_id = "+r.Address()+".id"))
	}
	return out
}

var _ ir.CrossResourceRule = mssqlNoExtAuditPolicy{}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-102: MSSQL auditing retention less than 90 days
// ---------------------------------------------------------------------------

type mssqlAuditRetentionLow struct{}

func (mssqlAuditRetentionLow) ID() string { return "AEGIS-AZURE-102" }
func (mssqlAuditRetentionLow) Title() string {
	return "MSSQL auditing retention less than 90 days"
}
func (mssqlAuditRetentionLow) Description() string {
	return "azurerm_mssql_server_extended_auditing_policy with " +
		"retention_in_days < 90 discards audit logs too early for " +
		"investigation. Retain at least 90 days."
}
func (mssqlAuditRetentionLow) Severity() ir.Severity { return ir.SeverityLow }

func (mssqlAuditRetentionLow) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server_extended_auditing_policy" ||
		resType == "azurerm_mssql_server"
}

// Check handles single-resource (policy) case; CheckAll handles server cross-resource
func (s mssqlAuditRetentionLow) Check(r ir.Resource) []ir.Finding {
	if r.Type == "azurerm_mssql_server" {
		return nil // handled by CheckAll
	}
	v, ok := r.Attributes["retention_in_days"]
	if !ok || !v.Known {
		return nil // absent or unresolved: cannot decide
	}
	var days float64
	switch n := v.Raw.(type) {
	case float64:
		days = n
	case int:
		days = float64(n)
	default:
		return nil // unexpected shape: stay quiet
	}
	if days == 0 {
		// Azure semantics: 0 = retain indefinitely.
		return nil
	}
	if days >= 90 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "retention_in_days", v.Span,
		"less than 90", "retention_in_days >= 90")}
}

// CheckAll: for servers without an auditing policy, retention is effectively 0 (< 90)
func (s mssqlAuditRetentionLow) CheckAll(resources []ir.Resource) []ir.Finding {
	// Build map of servers with adequate retention
	adequate := map[string]bool{}
	for _, r := range resources {
		if r.Type != "azurerm_mssql_server_extended_auditing_policy" {
			continue
		}
		v, ok := r.Attributes["retention_in_days"]
		if !ok || !v.Known {
			continue
		}
		var days float64
		switch n := v.Raw.(type) {
		case float64:
			days = n
		case int:
			days = float64(n)
		default:
			continue
		}
		if days == 0 || days >= 90 {
			// Mark all servers this policy references as adequate
			for _, addr := range refAddrs(r) {
				adequate[addr] = true
			}
		}
	}
	var out []ir.Finding
	for _, r := range resources {
		if r.Type != "azurerm_mssql_server" {
			continue
		}
		if adequate[r.Address()] {
			continue
		}
		// No adequate retention policy found
		out = append(out, mkFinding(s, r, "retention_in_days",
			evidenceSpan(ir.Span{}, r.Span), "absent or < 90",
			"retention_in_days >= 90"))
	}
	return out
}

var _ ir.CrossResourceRule = mssqlAuditRetentionLow{}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-103: MSSQL threat detection not set to all types
// ---------------------------------------------------------------------------

type mssqlThreatDetectPartial struct{}

func (mssqlThreatDetectPartial) ID() string { return "AEGIS-AZURE-103" }
func (mssqlThreatDetectPartial) Title() string {
	return "MSSQL threat detection not set to all types"
}
func (mssqlThreatDetectPartial) Description() string {
	return "azurerm_mssql_server_security_alert_policy with a non-empty " +
		"disabled_alerts set, or with state other than \"Enabled\", leaves " +
		"threat classes undetected. Enable all alert types."
}
func (mssqlThreatDetectPartial) Severity() ir.Severity { return ir.SeverityMedium }

func (mssqlThreatDetectPartial) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server_security_alert_policy"
}

func (s mssqlThreatDetectPartial) Check(r ir.Resource) []ir.Finding {
	var out []ir.Finding
	if state, span, present, known := getString(r, "state"); present && known {
		if !strings.EqualFold(strings.TrimSpace(state), "Enabled") {
			out = append(out, mkFinding(s, r, "state", span,
				state, "state = \"Enabled\""))
		}
	}
	if alerts, span, ok := getStringList(r, "disabled_alerts"); ok && len(alerts) > 0 {
		out = append(out, mkFinding(s, r, "disabled_alerts", span,
			strings.Join(alerts, ", "), "disabled_alerts = [] (all threat types enabled)"))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-104: MSSQL security alert email notifications disabled
// ---------------------------------------------------------------------------

type mssqlAlertEmailDisabled struct{}

func (mssqlAlertEmailDisabled) ID() string { return "AEGIS-AZURE-104" }
func (mssqlAlertEmailDisabled) Title() string {
	return "MSSQL security alert email notifications disabled"
}
func (mssqlAlertEmailDisabled) Description() string {
	return "azurerm_mssql_server_security_alert_policy with " +
		"email_account_admins absent or false leaves account admins without " +
		"threat alerts. Set email_account_admins = true."
}
func (mssqlAlertEmailDisabled) Severity() ir.Severity { return ir.SeverityLow }

func (mssqlAlertEmailDisabled) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server_security_alert_policy"
}

func (s mssqlAlertEmailDisabled) Check(r ir.Resource) []ir.Finding {
	// Explicitly documented insecure default: absent behaves as false.
	email, span, present, known := getBool(r, "email_account_admins")
	if !present {
		return []ir.Finding{mkFinding(s, r, "email_account_admins",
			evidenceSpan(ir.Span{}, r.Span), "absent (defaults to false)",
			"email_account_admins = true")}
	}
	if !known {
		return nil
	}
	if email {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "email_account_admins", span,
		"false", "email_account_admins = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-105: MSSQL server not using TLS 1.2
// ---------------------------------------------------------------------------

type mssqlTLSBelow12 struct{}

func (mssqlTLSBelow12) ID() string { return "AEGIS-AZURE-105" }
func (mssqlTLSBelow12) Title() string {
	return "MSSQL server not using TLS 1.2"
}
func (mssqlTLSBelow12) Description() string {
	return "azurerm_mssql_server with minimum_tls_version absent or below " +
		"\"1.2\" permits older, weaker protocol versions in transit. " +
		"Set minimum_tls_version = \"1.2\"."
}
func (mssqlTLSBelow12) Severity() ir.Severity { return ir.SeverityMedium }

func (mssqlTLSBelow12) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server"
}

func (s mssqlTLSBelow12) Check(r ir.Resource) []ir.Finding {
	// Explicitly documented insecure default: absent negotiates older TLS.
	ver, span, present, known := getString(r, "minimum_tls_version")
	if !present {
		return []ir.Finding{mkFinding(s, r, "minimum_tls_version",
			evidenceSpan(ir.Span{}, r.Span), "absent (defaults below 1.2)",
			"minimum_tls_version = \"1.2\"")}
	}
	if !known {
		return nil
	}
	if strings.TrimSpace(ver) == "1.2" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "minimum_tls_version", span,
		ver, "minimum_tls_version = \"1.2\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-106: MSSQL server allows public network access
// ---------------------------------------------------------------------------

type mssqlPublicAccessDefault struct{}

func (mssqlPublicAccessDefault) ID() string { return "AEGIS-AZURE-106" }
func (mssqlPublicAccessDefault) Title() string {
	return "MSSQL server allows public network access"
}
func (mssqlPublicAccessDefault) Description() string {
	return "azurerm_mssql_server with public_network_access_enabled true " +
		"or absent (provider default is true) exposes the database endpoint. " +
		"Set public_network_access_enabled = false and use private endpoints."
}
func (mssqlPublicAccessDefault) Severity() ir.Severity { return ir.SeverityHigh }

func (mssqlPublicAccessDefault) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server"
}

func (s mssqlPublicAccessDefault) Check(r ir.Resource) []ir.Finding {
	// Explicitly documented insecure default: absent behaves as true.
	pub, span, present, known := getBool(r, "public_network_access_enabled")
	if !present {
		return []ir.Finding{mkFinding(s, r, "public_network_access_enabled",
			evidenceSpan(ir.Span{}, r.Span), "absent (defaults to true)",
			"public_network_access_enabled = false")}
	}
	if !known {
		return nil
	}
	if !pub {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "public_network_access_enabled", span,
		"true", "public_network_access_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-107: MSSQL server without Azure AD authentication
// ---------------------------------------------------------------------------

type mssqlNoADAdminResource struct{}

func (mssqlNoADAdminResource) ID() string { return "AEGIS-AZURE-107" }
func (mssqlNoADAdminResource) Title() string {
	return "MSSQL server without Azure AD authentication"
}
func (mssqlNoADAdminResource) Description() string {
	return "azurerm_mssql_server with no azurerm_mssql_server_azuread_administrator " +
		"referencing it relies solely on SQL authentication. Configure an " +
		"Azure AD administrator for centralized identity."
}
func (mssqlNoADAdminResource) Severity() ir.Severity { return ir.SeverityMedium }

func (mssqlNoADAdminResource) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server"
}

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (mssqlNoADAdminResource) Check(ir.Resource) []ir.Finding { return nil }

func (mssqlNoADAdminResource) CheckAll(resources []ir.Resource) []ir.Finding {
	s := mssqlNoADAdminResource{}
	withAdmin := map[string]bool{}
	for _, r := range resources {
		if r.Type != "azurerm_mssql_server_azuread_administrator" {
			continue
		}
		for _, addr := range refAddrs(r) {
			withAdmin[addr] = true
		}
	}
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	var out []ir.Finding
	for _, r := range sorted {
		if r.Type != "azurerm_mssql_server" {
			continue
		}
		// Inline block also counts as an AD admin.
		if _, _, present, _ := getBlocks(r, "azuread_administrator"); present {
			continue
		}
		if withAdmin[r.Address()] {
			continue
		}
		out = append(out, mkFinding(s, r, "azuread_administrator",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"azurerm_mssql_server_azuread_administrator with server_id = "+r.Address()+".id"))
	}
	return out
}

var _ ir.CrossResourceRule = mssqlNoADAdminResource{}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-108: MSSQL server without private endpoint
// ---------------------------------------------------------------------------

type mssqlNoPrivateEndpoint struct{}

func (mssqlNoPrivateEndpoint) ID() string { return "AEGIS-AZURE-108" }
func (mssqlNoPrivateEndpoint) Title() string {
	return "MSSQL server without private endpoint"
}
func (mssqlNoPrivateEndpoint) Description() string {
	return "azurerm_mssql_server with no azurerm_private_endpoint whose " +
		"private_service_connection targets it keeps database traffic off " +
		"the private network. Add a private endpoint with subresource " +
		"\"sqlServer\"."
}
func (mssqlNoPrivateEndpoint) Severity() ir.Severity { return ir.SeverityMedium }

func (mssqlNoPrivateEndpoint) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server"
}

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (mssqlNoPrivateEndpoint) Check(ir.Resource) []ir.Finding { return nil }

func (mssqlNoPrivateEndpoint) CheckAll(resources []ir.Resource) []ir.Finding {
	s := mssqlNoPrivateEndpoint{}
	withPE := map[string]bool{}
	for _, r := range resources {
		if r.Type != "azurerm_private_endpoint" {
			continue
		}
		blks, _, present, known := getBlocks(r, "private_service_connection")
		if !present || !known {
			continue
		}
		for _, blk := range blks {
			for _, addr := range refAddrsOfValue(blk) {
				withPE[addr] = true
			}
		}
	}
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	var out []ir.Finding
	for _, r := range sorted {
		if r.Type != "azurerm_mssql_server" {
			continue
		}
		if withPE[r.Address()] {
			continue
		}
		out = append(out, mkFinding(s, r, "private_endpoint",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"azurerm_private_endpoint with private_service_connection targeting "+r.Address()))
	}
	return out
}

var _ ir.CrossResourceRule = mssqlNoPrivateEndpoint{}

// refAddrs collects every "type.name" resource address reachable through
// reference values in a resource's attributes (best-effort correlation;
// references resolved to module outputs or computed values simply match
// nothing and the rule stays quiet for them).
func refAddrs(r ir.Resource) []string {
	out := map[string]bool{}
	var walk func(v ir.Value)
	walk = func(v ir.Value) {
		if v.IsRef() {
			if addr, ok := refAddrOf(v.Ref); ok {
				out[addr] = true
			}
			return
		}
		switch t := v.Raw.(type) {
		case []ir.Value:
			for _, item := range t {
				walk(item)
			}
		case map[string]ir.Value:
			for _, item := range t {
				walk(item)
			}
		}
	}
	for _, v := range r.Attributes {
		walk(v)
	}
	addrs := make([]string, 0, len(out))
	for a := range out {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	return addrs
}

// refAddrsOfValue collects reference addresses from a nested block map.
func refAddrsOfValue(m map[string]ir.Value) []string {
	out := map[string]bool{}
	var walk func(v ir.Value)
	walk = func(v ir.Value) {
		if v.IsRef() {
			if addr, ok := refAddrOf(v.Ref); ok {
				out[addr] = true
			}
			return
		}
		switch t := v.Raw.(type) {
		case []ir.Value:
			for _, item := range t {
				walk(item)
			}
		case map[string]ir.Value:
			for _, item := range t {
				walk(item)
			}
		}
	}
	for _, v := range m {
		walk(v)
	}
	addrs := make([]string, 0, len(out))
	for a := range out {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	return addrs
}

// refAddrOf reduces a dotted reference (e.g. "azurerm_mssql_server.db.id")
// to its "type.name" address.
func refAddrOf(ref string) (string, bool) {
	parts := strings.Split(ref, ".")
	if len(parts) < 2 {
		return "", false
	}
	return parts[0] + "." + parts[1], true
}
