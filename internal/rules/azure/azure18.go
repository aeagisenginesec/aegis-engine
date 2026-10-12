// Package azure — monitoring, Defender & container registry round
// (AEGIS-AZURE-246..261).
//
// Covers Microsoft Defender for Cloud plan tiers, Security Center
// contacts, Log Analytics hardening, and Container Registry hardening
// (trust policy, anonymous pull, network rules, admin account, public
// network, export policy).
//
// Absent-attribute policy for this file: absent yields a finding when the
// provider default is insecure. Present-but-unresolved yields NO finding.
package azure

import (
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// Azure18Rules returns monitoring, Defender & ACR rules in ID order.
func Azure18Rules() []ir.Rule {
	return []ir.Rule{
		defenderPlanNotStandard{}, // AEGIS-AZURE-246
		secContactNoNotify{},      // AEGIS-AZURE-247
		logAnalyticsLowRetain{},   // AEGIS-AZURE-248
		logAnalyticsPubIngest{},   // AEGIS-AZURE-249
		logAnalyticsPubQuery{},    // AEGIS-AZURE-250
		acrNoTrustPolicy{},        // AEGIS-AZURE-251
		acrAnonPull{},             // AEGIS-AZURE-252
		acrNetRulesOpen{},         // AEGIS-AZURE-253
		acrExportPolicyOn{},       // AEGIS-AZURE-254
		acrPublicNet{},            // AEGIS-AZURE-255
		acrTaskRuns{},             // AEGIS-AZURE-256
		acrNoCMK{},                // AEGIS-AZURE-257
		appInsightsLowRetain{},    // AEGIS-AZURE-258
		logAnalyticsNoCMK{},       // AEGIS-AZURE-259
		defenderARMPlanOff{},      // AEGIS-AZURE-260
		acrRetentionOff{},         // AEGIS-AZURE-261
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-246: Defender for Cloud plan not Standard
// ---------------------------------------------------------------------------

type defenderPlanNotStandard struct{}

func (defenderPlanNotStandard) ID() string { return "AEGIS-AZURE-246" }
func (defenderPlanNotStandard) Title() string {
	return "Defender for Cloud plan not Standard tier"
}
func (defenderPlanNotStandard) Description() string {
	return "azurerm_security_center_subscription_pricing with tier " +
		"other than \"Standard\" leaves the resource type on the free " +
		"tier without threat protection, JIT access and vulnerability " +
		"assessment. Enable the Standard plan per resource type."
}
func (defenderPlanNotStandard) Severity() ir.Severity { return ir.SeverityHigh }

func (defenderPlanNotStandard) AppliesTo(resType string) bool {
	return resType == "azurerm_security_center_subscription_pricing"
}

func (s defenderPlanNotStandard) Check(r ir.Resource) []ir.Finding {
	tier, span, present, known := getString(r, "tier")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(tier), "Standard") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "tier", span,
		tier, "tier = \"Standard\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-247: Security Center contact without notifications
// ---------------------------------------------------------------------------

type secContactNoNotify struct{}

func (secContactNoNotify) ID() string { return "AEGIS-AZURE-247" }
func (secContactNoNotify) Title() string {
	return "Security Center contact without alert notifications"
}
func (secContactNoNotify) Description() string {
	return "azurerm_security_center_contact with " +
		"alert_notifications = false (or absent) means security alerts " +
		"never reach the designated contact. Enable alert notifications " +
		"and alerts to admins."
}
func (secContactNoNotify) Severity() ir.Severity { return ir.SeverityLow }

func (secContactNoNotify) AppliesTo(resType string) bool {
	return resType == "azurerm_security_center_contact"
}

func (s secContactNoNotify) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "alert_notifications",
		"alert_notifications = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-248: Log Analytics retention under 90 days
// ---------------------------------------------------------------------------

type logAnalyticsLowRetain struct{}

func (logAnalyticsLowRetain) ID() string { return "AEGIS-AZURE-248" }
func (logAnalyticsLowRetain) Title() string {
	return "Log Analytics workspace retention under 90 days"
}
func (logAnalyticsLowRetain) Description() string {
	return "azurerm_log_analytics_workspace with retention_in_days " +
		"below 90 truncates the security investigation window. Keep at " +
		"least 90 days for incident response."
}
func (logAnalyticsLowRetain) Severity() ir.Severity { return ir.SeverityMedium }

func (logAnalyticsLowRetain) AppliesTo(resType string) bool {
	return resType == "azurerm_log_analytics_workspace"
}

func (s logAnalyticsLowRetain) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["retention_in_days"]
	if !ok || !v.Known {
		return nil
	}
	var days float64
	switch n := v.Raw.(type) {
	case float64:
		days = n
	case int:
		days = float64(n)
	case int64:
		days = float64(n)
	default:
		return nil
	}
	if days >= 90 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "retention_in_days", v.Span,
		strings.TrimRight(strings.TrimRight(strconv.FormatFloat(days, 'f', 1, 64), "0"), "."),
		"retention_in_days = 90")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-249: Log Analytics with public ingestion
// ---------------------------------------------------------------------------

type logAnalyticsPubIngest struct{}

func (logAnalyticsPubIngest) ID() string { return "AEGIS-AZURE-249" }
func (logAnalyticsPubIngest) Title() string {
	return "Log Analytics workspace with public ingestion"
}
func (logAnalyticsPubIngest) Description() string {
	return "azurerm_log_analytics_workspace with " +
		"internet_ingestion_enabled (the provider default) accepts log " +
		"ingestion over the public internet. Disable it and ingest " +
		"through private link (AMPLS)."
}
func (logAnalyticsPubIngest) Severity() ir.Severity { return ir.SeverityMedium }

func (logAnalyticsPubIngest) AppliesTo(resType string) bool {
	return resType == "azurerm_log_analytics_workspace"
}

func (s logAnalyticsPubIngest) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "internet_ingestion_enabled")
	if present && !known {
		return nil
	}
	if present && !en {
		return nil
	}
	actual := "true"
	if !present {
		actual = "absent (provider default: enabled)"
	}
	return []ir.Finding{mkFinding(s, r, "internet_ingestion_enabled",
		evidenceSpan(span, r.Span), actual,
		"internet_ingestion_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-250: Log Analytics with public query access
// ---------------------------------------------------------------------------

type logAnalyticsPubQuery struct{}

func (logAnalyticsPubQuery) ID() string { return "AEGIS-AZURE-250" }
func (logAnalyticsPubQuery) Title() string {
	return "Log Analytics workspace with public query access"
}
func (logAnalyticsPubQuery) Description() string {
	return "azurerm_log_analytics_workspace with " +
		"internet_query_enabled (the provider default) allows log " +
		"queries over the public internet. Disable it and query " +
		"through private link."
}
func (logAnalyticsPubQuery) Severity() ir.Severity { return ir.SeverityMedium }

func (logAnalyticsPubQuery) AppliesTo(resType string) bool {
	return resType == "azurerm_log_analytics_workspace"
}

func (s logAnalyticsPubQuery) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "internet_query_enabled")
	if present && !known {
		return nil
	}
	if present && !en {
		return nil
	}
	actual := "true"
	if !present {
		actual = "absent (provider default: enabled)"
	}
	return []ir.Finding{mkFinding(s, r, "internet_query_enabled",
		evidenceSpan(span, r.Span), actual,
		"internet_query_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-251: Container Registry without content trust
// ---------------------------------------------------------------------------

type acrNoTrustPolicy struct{}

func (acrNoTrustPolicy) ID() string { return "AEGIS-AZURE-251" }
func (acrNoTrustPolicy) Title() string {
	return "Container Registry without content trust"
}
func (acrNoTrustPolicy) Description() string {
	return "azurerm_container_registry without trust_policy_enabled = " +
		"true (Premium SKU) cannot enforce signed-image policies, so " +
		"tampered images can be pulled. Enable content trust."
}
func (acrNoTrustPolicy) Severity() ir.Severity { return ir.SeverityMedium }

func (acrNoTrustPolicy) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrNoTrustPolicy) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "trust_policy_enabled",
		"trust_policy_enabled = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-252: Container Registry with anonymous pull
// ---------------------------------------------------------------------------

type acrAnonPull struct{}

func (acrAnonPull) ID() string { return "AEGIS-AZURE-252" }
func (acrAnonPull) Title() string {
	return "Container Registry with anonymous pull enabled"
}
func (acrAnonPull) Description() string {
	return "azurerm_container_registry with anonymous_pull_enabled = " +
		"true lets anyone pull images without authentication, leaking " +
		"proprietary code and layers. Disable anonymous pull."
}
func (acrAnonPull) Severity() ir.Severity { return ir.SeverityHigh }

func (acrAnonPull) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrAnonPull) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "anonymous_pull_enabled")
	if !present || !known {
		return nil // default false: secure
	}
	if !en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "anonymous_pull_enabled", span,
		"true", "anonymous_pull_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-253: Container Registry network rules allow public traffic
// ---------------------------------------------------------------------------

type acrNetRulesOpen struct{}

func (acrNetRulesOpen) ID() string { return "AEGIS-AZURE-253" }
func (acrNetRulesOpen) Title() string {
	return "Container Registry network rules allow public traffic"
}
func (acrNetRulesOpen) Description() string {
	return "azurerm_container_registry network_rule_set with " +
		"default_action other than \"Deny\" accepts registry traffic " +
		"from any network. Set default_action = \"Deny\" with explicit " +
		"allowances."
}
func (acrNetRulesOpen) Severity() ir.Severity { return ir.SeverityHigh }

func (acrNetRulesOpen) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrNetRulesOpen) Check(r ir.Resource) []ir.Finding {
	nrs, span, present, known := getBlocks(r, "network_rule_set")
	if !present || !known {
		return nil
	}
	for _, nr := range nrs {
		act, _, p, k := blockString(nr, "default_action")
		if p && !k {
			return nil
		}
		if !p || !strings.EqualFold(strings.TrimSpace(act), "Deny") {
			actual := "absent"
			if p {
				actual = act
			}
			return []ir.Finding{mkFinding(s, r, "network_rule_set",
				evidenceSpan(span, r.Span), actual,
				"network_rule_set { default_action = \"Deny\" }")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-254: Container Registry with export policy enabled
// ---------------------------------------------------------------------------

type acrExportPolicyOn struct{}

func (acrExportPolicyOn) ID() string { return "AEGIS-AZURE-254" }
func (acrExportPolicyOn) Title() string {
	return "Container Registry with export policy enabled"
}
func (acrExportPolicyOn) Description() string {
	return "azurerm_container_registry with export_policy_enabled = " +
		"true allows images to be exported out of the registry, " +
		"aiding exfiltration of proprietary images. Disable export " +
		"unless cross-registry replication is required."
}
func (acrExportPolicyOn) Severity() ir.Severity { return ir.SeverityLow }

func (acrExportPolicyOn) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrExportPolicyOn) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "export_policy_enabled")
	if !present || !known {
		return nil // default true in provider, but only flag explicit
	}
	if !en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "export_policy_enabled", span,
		"true", "export_policy_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-255: Container Registry with public network access
// ---------------------------------------------------------------------------

type acrPublicNet struct{}

func (acrPublicNet) ID() string { return "AEGIS-AZURE-255" }
func (acrPublicNet) Title() string {
	return "Container Registry with public network access enabled"
}
func (acrPublicNet) Description() string {
	return "azurerm_container_registry with " +
		"public_network_access_enabled (the provider default) serves " +
		"the registry over the public internet. Disable it and use " +
		"private endpoints."
}
func (acrPublicNet) Severity() ir.Severity { return ir.SeverityHigh }

func (acrPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_container_registry")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-256: Container Registry task with secrets in commands
// ---------------------------------------------------------------------------

type acrTaskRuns struct{}

func (acrTaskRuns) ID() string { return "AEGIS-AZURE-256" }
func (acrTaskRuns) Title() string {
	return "Container Registry task exposing secrets in commands"
}
func (acrTaskRuns) Description() string {
	return "azurerm_container_registry_task with plaintext secrets in " +
		"encoded_values or values runs secrets through task logs. Use " +
		"Key Vault references via secret_values instead."
}
func (acrTaskRuns) Severity() ir.Severity { return ir.SeverityMedium }

func (acrTaskRuns) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry_task"
}

func (s acrTaskRuns) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["encoded_values"]
	if !ok {
		return nil
	}
	if !v.Known {
		return nil
	}
	m, mok := v.AsMap()
	if !mok {
		return nil
	}
	for k := range m {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "password") || strings.Contains(lk, "secret") ||
			strings.Contains(lk, "token") || strings.Contains(lk, "key") {
			return []ir.Finding{mkFinding(s, r, "encoded_values", v.Span,
				"secret-like value: "+k,
				"use secret_values with Key Vault references")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-257: Container Registry without customer-managed key
// ---------------------------------------------------------------------------

type acrNoCMK struct{}

func (acrNoCMK) ID() string { return "AEGIS-AZURE-257" }
func (acrNoCMK) Title() string {
	return "Container Registry without customer-managed key"
}
func (acrNoCMK) Description() string {
	return "azurerm_container_registry (Premium) without an " +
		"encryption block using a Key Vault key relies on " +
		"Microsoft-managed keys. Configure customer-managed keys."
}
func (acrNoCMK) Severity() ir.Severity { return ir.SeverityMedium }

func (acrNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrNoCMK) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "encryption")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "encryption",
		evidenceSpan(span, r.Span), "absent (Microsoft-managed keys)",
		"encryption { key_vault_key_id = \"...\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-258: Application Insights retention under 90 days
// ---------------------------------------------------------------------------

type appInsightsLowRetain struct{}

func (appInsightsLowRetain) ID() string { return "AEGIS-AZURE-258" }
func (appInsightsLowRetain) Title() string {
	return "Application Insights retention under 90 days"
}
func (appInsightsLowRetain) Description() string {
	return "azurerm_application_insights with retention_in_days below " +
		"90 truncates telemetry needed for security investigations. " +
		"Keep at least 90 days."
}
func (appInsightsLowRetain) Severity() ir.Severity { return ir.SeverityLow }

func (appInsightsLowRetain) AppliesTo(resType string) bool {
	return resType == "azurerm_application_insights"
}

func (s appInsightsLowRetain) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["retention_in_days"]
	if !ok || !v.Known {
		return nil // default 90: secure
	}
	var days float64
	switch n := v.Raw.(type) {
	case float64:
		days = n
	case int:
		days = float64(n)
	case int64:
		days = float64(n)
	default:
		return nil
	}
	if days >= 90 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "retention_in_days", v.Span,
		strings.TrimRight(strings.TrimRight(strconv.FormatFloat(days, 'f', 1, 64), "0"), "."),
		"retention_in_days = 90")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-259: Log Analytics workspace without customer-managed key
// ---------------------------------------------------------------------------

type logAnalyticsNoCMK struct{}

func (logAnalyticsNoCMK) ID() string { return "AEGIS-AZURE-259" }
func (logAnalyticsNoCMK) Title() string {
	return "Log Analytics workspace without customer-managed key"
}
func (logAnalyticsNoCMK) Description() string {
	return "azurerm_log_analytics_workspace without a " +
		"customer_managed_key reference relies on Microsoft-managed " +
		"keys for log data. Configure CMK for sensitive log data."
}
func (logAnalyticsNoCMK) Severity() ir.Severity { return ir.SeverityMedium }

func (logAnalyticsNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_log_analytics_workspace"
}

func (s logAnalyticsNoCMK) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["customer_managed_key_id"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "customer_managed_key_id", r.Span,
			"absent (Microsoft-managed keys)",
			"customer_managed_key_id = \"...\"")}
	}
	if !v.Known {
		return nil
	}
	sv, kok := v.AsString()
	if !kok || strings.TrimSpace(sv) == "" {
		return []ir.Finding{mkFinding(s, r, "customer_managed_key_id", v.Span,
			"empty", "customer_managed_key_id = \"...\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-260: Defender for ARM not Standard
// ---------------------------------------------------------------------------

type defenderARMPlanOff struct{}

func (defenderARMPlanOff) ID() string { return "AEGIS-AZURE-260" }
func (defenderARMPlanOff) Title() string {
	return "Defender for Resource Manager plan not enabled"
}
func (defenderARMPlanOff) Description() string {
	return "Microsoft Defender for Resource Manager (the " +
		"\"Arm\" pricing plan) detects suspicious management-plane " +
		"operations. Enable the Standard tier for the Arm resource " +
		"type via azurerm_security_center_subscription_pricing."
}
func (defenderARMPlanOff) Severity() ir.Severity { return ir.SeverityMedium }

func (defenderARMPlanOff) AppliesTo(resType string) bool {
	return resType == "azurerm_security_center_subscription_pricing"
}

func (s defenderARMPlanOff) Check(r ir.Resource) []ir.Finding {
	rt, _, rpresent, rknown := getString(r, "resource_type")
	tier, span, tpresent, tknown := getString(r, "tier")
	if !rpresent || !rknown || !tpresent || !tknown {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(rt), "Arm") {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(tier), "Standard") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "tier", span,
		tier, "tier = \"Standard\" for resource_type = \"Arm\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-261: Container Registry without retention policy
// ---------------------------------------------------------------------------

type acrRetentionOff struct{}

func (acrRetentionOff) ID() string { return "AEGIS-AZURE-261" }
func (acrRetentionOff) Title() string {
	return "Container Registry without retention policy"
}
func (acrRetentionOff) Description() string {
	return "azurerm_container_registry (Premium) without a " +
		"retention_policy block accumulates untagged manifests " +
		"indefinitely, widening the stale-image attack surface. Enable " +
		"retention with a sensible day count."
}
func (acrRetentionOff) Severity() ir.Severity { return ir.SeverityLow }

func (acrRetentionOff) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrRetentionOff) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "retention_policy")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		for _, b := range blks {
			en, _, p, k := blockBool(b, "enabled")
			if p && !k {
				return nil
			}
			if p && en {
				return nil
			}
		}
		return []ir.Finding{mkFinding(s, r, "retention_policy",
			evidenceSpan(span, r.Span), "present but not enabled",
			"retention_policy { enabled = true, days = 7 }")}
	}
	return []ir.Finding{mkFinding(s, r, "retention_policy",
		evidenceSpan(span, r.Span), "absent",
		"retention_policy { enabled = true, days = 7 }")}
}
