// Package azure — CosmosDB, ACR, monitoring and misc rules (AEGIS-AZURE-081..100).
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure6Rules returns CosmosDB, ACR, monitoring and misc rules in ID order.
func Azure6Rules() []ir.Rule {
	return []ir.Rule{
		cosmosNoIPFilter{},       // AEGIS-AZURE-081
		cosmosNoBackup{},         // AEGIS-AZURE-082
		cosmosWeakConsistency{},  // AEGIS-AZURE-083
		cosmosPublicAccess{},     // AEGIS-AZURE-084
		cosmosNoCMK{},            // AEGIS-AZURE-085
		acrNoGeoReplication{},    // AEGIS-AZURE-086
		acrNoNetworkRules{},      // AEGIS-AZURE-087
		acrNoContentTrust{},      // AEGIS-AZURE-088
		acrNoQuarantine{},        // AEGIS-AZURE-089
		acrPublicAccess{},        // AEGIS-AZURE-090
		monitorNoActivityLog{},   // AEGIS-AZURE-091
		monitorShortRetention{},  // AEGIS-AZURE-092
		appInsightsNoRetention{}, // AEGIS-AZURE-093
		eventHubNoCMK{},          // AEGIS-AZURE-094
		serviceBusNoCMK{},        // AEGIS-AZURE-095
		postgresNoSSL{},          // AEGIS-AZURE-096
		mysqlNoSSL{},             // AEGIS-AZURE-097
		mariadbNoSSL{},           // AEGIS-AZURE-098
		frontdoorNoWAF{},         // AEGIS-AZURE-099
		trafficMgrNoHTTPS{},      // AEGIS-AZURE-100
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-081: CosmosDB without IP filtering
// ---------------------------------------------------------------------------

type cosmosNoIPFilter struct{}

func (cosmosNoIPFilter) ID() string { return "AEGIS-AZURE-081" }
func (cosmosNoIPFilter) Title() string {
	return "CosmosDB account without IP range filter"
}
func (cosmosNoIPFilter) Description() string {
	return "azurerm_cosmosdb_account without ip_range_filter accepts " +
		"connections from anywhere. Restrict with an IP range filter."
}
func (cosmosNoIPFilter) Severity() ir.Severity { return ir.SeverityHigh }

func (cosmosNoIPFilter) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosNoIPFilter) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getString(r, "ip_range_filter")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "ip_range_filter",
		evidenceSpan(ir.Span{}, r.Span), "absent", "ip_range_filter = \"203.0.113.0/24\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-082: CosmosDB without backup policy
// ---------------------------------------------------------------------------

type cosmosNoBackup struct{}

func (cosmosNoBackup) ID() string { return "AEGIS-AZURE-082" }
func (cosmosNoBackup) Title() string {
	return "CosmosDB account without backup configuration"
}
func (cosmosNoBackup) Description() string {
	return "azurerm_cosmosdb_account without backup block uses defaults " +
		"that may not meet RPO. Configure periodic backup with retention."
}
func (cosmosNoBackup) Severity() ir.Severity { return ir.SeverityMedium }

func (cosmosNoBackup) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosNoBackup) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getBlocks(r, "backup")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "backup",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"backup { type = \"Periodic\" interval_in_minutes = 240 retention_in_hours = 720 }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-083: CosmosDB with weak consistency level
// ---------------------------------------------------------------------------

type cosmosWeakConsistency struct{}

func (cosmosWeakConsistency) ID() string { return "AEGIS-AZURE-083" }
func (cosmosWeakConsistency) Title() string {
	return "CosmosDB account with eventual consistency"
}
func (cosmosWeakConsistency) Description() string {
	return "azurerm_cosmosdb_account with consistency_policy level = \"Eventual\" " +
		"risks stale reads for sensitive workloads. Prefer Session or stronger."
}
func (cosmosWeakConsistency) Severity() ir.Severity { return ir.SeverityLow }

func (cosmosWeakConsistency) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosWeakConsistency) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "consistency_policy")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	lvl, _, lp, lk := blockString(blks[0], "consistency_level")
	if !lp || !lk {
		return nil
	}
	if strings.EqualFold(lvl, "Eventual") {
		return []ir.Finding{mkFinding(s, r, "consistency_policy.consistency_level",
			evidenceSpan(ir.Span{}, r.Span), lvl, "consistency_level = \"Session\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-084: CosmosDB with public network access
// ---------------------------------------------------------------------------

type cosmosPublicAccess struct{}

func (cosmosPublicAccess) ID() string { return "AEGIS-AZURE-084" }
func (cosmosPublicAccess) Title() string {
	return "CosmosDB account with public network access"
}
func (cosmosPublicAccess) Description() string {
	return "azurerm_cosmosdb_account with public_network_access_enabled = true " +
		"exposes the database endpoint. Disable public access."
}
func (cosmosPublicAccess) Severity() ir.Severity { return ir.SeverityHigh }

func (cosmosPublicAccess) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosPublicAccess) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "public_network_access_enabled")
	if !present || !known {
		return nil
	}
	if !pub {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "public_network_access_enabled", span,
		"true", "public_network_access_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-085: CosmosDB without customer-managed key
// ---------------------------------------------------------------------------

type cosmosNoCMK struct{}

func (cosmosNoCMK) ID() string { return "AEGIS-AZURE-085" }
func (cosmosNoCMK) Title() string {
	return "CosmosDB account without customer-managed key"
}
func (cosmosNoCMK) Description() string {
	return "azurerm_cosmosdb_account without key_vault_key_id uses " +
		"Microsoft-managed keys. Use a customer-managed key for sensitive data."
}
func (cosmosNoCMK) Severity() ir.Severity { return ir.SeverityLow }

func (cosmosNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosNoCMK) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getString(r, "key_vault_key_id")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "key_vault_key_id",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"key_vault_key_id = azurerm_key_vault_key.example.id")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-086: Container Registry without geo-replication
// ---------------------------------------------------------------------------

type acrNoGeoReplication struct{}

func (acrNoGeoReplication) ID() string { return "AEGIS-AZURE-086" }
func (acrNoGeoReplication) Title() string {
	return "Container Registry without geo-replication"
}
func (acrNoGeoReplication) Description() string {
	return "azurerm_container_registry premium without georeplications " +
		"lacks regional resilience. Configure geo-replication for production."
}
func (acrNoGeoReplication) Severity() ir.Severity { return ir.SeverityLow }

func (acrNoGeoReplication) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrNoGeoReplication) Check(r ir.Resource) []ir.Finding {
	sku, _, spresent, sknown := getString(r, "sku")
	if !spresent || !sknown || !strings.EqualFold(sku, "Premium") {
		return nil // geo-replication requires Premium
	}
	_, _, present, _ := getBlocks(r, "georeplications")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "georeplications",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"georeplications { location = \"westeurope\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-087: Container Registry without network rule set
// ---------------------------------------------------------------------------

type acrNoNetworkRules struct{}

func (acrNoNetworkRules) ID() string { return "AEGIS-AZURE-087" }
func (acrNoNetworkRules) Title() string {
	return "Container Registry without network restrictions"
}
func (acrNoNetworkRules) Description() string {
	return "azurerm_container_registry premium without network_rule_set " +
		"accepts pulls from anywhere. Restrict with default_action = \"Deny\"."
}
func (acrNoNetworkRules) Severity() ir.Severity { return ir.SeverityMedium }

func (acrNoNetworkRules) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrNoNetworkRules) Check(r ir.Resource) []ir.Finding {
	sku, _, spresent, sknown := getString(r, "sku")
	if !spresent || !sknown || !strings.EqualFold(sku, "Premium") {
		return nil
	}
	_, _, present, _ := getBlocks(r, "network_rule_set")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "network_rule_set",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"network_rule_set { default_action = \"Deny\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-088: Container Registry without content trust
// ---------------------------------------------------------------------------

type acrNoContentTrust struct{}

func (acrNoContentTrust) ID() string { return "AEGIS-AZURE-088" }
func (acrNoContentTrust) Title() string {
	return "Container Registry without content trust"
}
func (acrNoContentTrust) Description() string {
	return "azurerm_container_registry with trust_policy disabled allows " +
		"unsigned images. Enable content trust for image signing."
}
func (acrNoContentTrust) Severity() ir.Severity { return ir.SeverityMedium }

func (acrNoContentTrust) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrNoContentTrust) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "trust_policy")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	en, _, ep, ek := blockString(blks[0], "enabled")
	if !ep || !ek {
		return nil
	}
	if strings.EqualFold(en, "true") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "trust_policy.enabled",
		evidenceSpan(ir.Span{}, r.Span), en, "trust_policy { enabled = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-089: Container Registry without quarantine policy
// ---------------------------------------------------------------------------

type acrNoQuarantine struct{}

func (acrNoQuarantine) ID() string { return "AEGIS-AZURE-089" }
func (acrNoQuarantine) Title() string {
	return "Container Registry without quarantine policy"
}
func (acrNoQuarantine) Description() string {
	return "azurerm_container_registry with quarantine_policy disabled " +
		"allows unscanned images to be pulled. Enable quarantine."
}
func (acrNoQuarantine) Severity() ir.Severity { return ir.SeverityLow }

func (acrNoQuarantine) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrNoQuarantine) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "quarantine_policy")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	en, _, ep, ek := blockString(blks[0], "enabled")
	if !ep || !ek {
		return nil
	}
	if strings.EqualFold(en, "true") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "quarantine_policy.enabled",
		evidenceSpan(ir.Span{}, r.Span), en, "quarantine_policy { enabled = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-090: Container Registry with public network access
// ---------------------------------------------------------------------------

type acrPublicAccess struct{}

func (acrPublicAccess) ID() string { return "AEGIS-AZURE-090" }
func (acrPublicAccess) Title() string {
	return "Container Registry with public network access"
}
func (acrPublicAccess) Description() string {
	return "azurerm_container_registry with public_network_access_enabled = true " +
		"exposes the registry endpoint. Disable public access."
}
func (acrPublicAccess) Severity() ir.Severity { return ir.SeverityMedium }

func (acrPublicAccess) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrPublicAccess) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "public_network_access_enabled")
	if !present || !known {
		return nil
	}
	if !pub {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "public_network_access_enabled", span,
		"true", "public_network_access_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-091: Monitor log profile without retention
// ---------------------------------------------------------------------------

type monitorNoActivityLog struct{}

func (monitorNoActivityLog) ID() string { return "AEGIS-AZURE-091" }
func (monitorNoActivityLog) Title() string {
	return "Monitor log profile without categories"
}
func (monitorNoActivityLog) Description() string {
	return "azurerm_monitor_log_profile without categories misses activity " +
		"log capture. Include Write, Delete, and Action categories."
}
func (monitorNoActivityLog) Severity() ir.Severity { return ir.SeverityMedium }

func (monitorNoActivityLog) AppliesTo(resType string) bool {
	return resType == "azurerm_monitor_log_profile"
}

func (s monitorNoActivityLog) Check(r ir.Resource) []ir.Finding {
	if _, _, ok := getStringList(r, "categories"); ok {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "categories",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"categories = [\"Write\", \"Delete\", \"Action\"]")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-092: Monitor log profile with short retention
// ---------------------------------------------------------------------------

type monitorShortRetention struct{}

func (monitorShortRetention) ID() string { return "AEGIS-AZURE-092" }
func (monitorShortRetention) Title() string {
	return "Monitor log profile with short retention"
}
func (monitorShortRetention) Description() string {
	return "azurerm_monitor_log_profile retention_policy with days < 365 " +
		"loses long-term audit trail. Retain logs at least 365 days."
}
func (monitorShortRetention) Severity() ir.Severity { return ir.SeverityLow }

func (monitorShortRetention) AppliesTo(resType string) bool {
	return resType == "azurerm_monitor_log_profile"
}

func (s monitorShortRetention) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "retention_policy")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	dv, ok := blks[0]["days"]
	if !ok || !dv.Known {
		return nil
	}
	var days float64
	switch n := dv.Raw.(type) {
	case float64:
		days = n
	case int:
		days = float64(n)
	default:
		return nil
	}
	if days >= 365 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "retention_policy.days",
		dv.Span, "less than 365", "days = 365")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-093: Application Insights with short retention
// ---------------------------------------------------------------------------

type appInsightsNoRetention struct{}

func (appInsightsNoRetention) ID() string { return "AEGIS-AZURE-093" }
func (appInsightsNoRetention) Title() string {
	return "Application Insights with short retention"
}
func (appInsightsNoRetention) Description() string {
	return "azurerm_application_insights with retention_in_days < 90 " +
		"loses telemetry history. Retain at least 90 days."
}
func (appInsightsNoRetention) Severity() ir.Severity { return ir.SeverityLow }

func (appInsightsNoRetention) AppliesTo(resType string) bool {
	return resType == "azurerm_application_insights"
}

func (s appInsightsNoRetention) Check(r ir.Resource) []ir.Finding {
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
	default:
		return nil
	}
	if days >= 90 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "retention_in_days",
		v.Span, "less than 90", "retention_in_days = 90")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-094: Event Hub namespace without customer-managed key
// ---------------------------------------------------------------------------

type eventHubNoCMK struct{}

func (eventHubNoCMK) ID() string { return "AEGIS-AZURE-094" }
func (eventHubNoCMK) Title() string {
	return "Event Hub namespace without customer-managed key"
}
func (eventHubNoCMK) Description() string {
	return "azurerm_eventhub_namespace without customer_managed_key uses " +
		"Microsoft-managed keys. Use a customer-managed key for sensitive streams."
}
func (eventHubNoCMK) Severity() ir.Severity { return ir.SeverityLow }

func (eventHubNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_eventhub_namespace"
}

func (s eventHubNoCMK) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getBlocks(r, "customer_managed_key")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "customer_managed_key",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"customer_managed_key { key_vault_key_id = ... }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-095: Service Bus namespace without customer-managed key
// ---------------------------------------------------------------------------

type serviceBusNoCMK struct{}

func (serviceBusNoCMK) ID() string { return "AEGIS-AZURE-095" }
func (serviceBusNoCMK) Title() string {
	return "Service Bus namespace without customer-managed key"
}
func (serviceBusNoCMK) Description() string {
	return "azurerm_servicebus_namespace with customer_managed_key block " +
		"absent uses Microsoft-managed keys. Use a customer-managed key."
}
func (serviceBusNoCMK) Severity() ir.Severity { return ir.SeverityLow }

func (serviceBusNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_servicebus_namespace"
}

func (s serviceBusNoCMK) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getBlocks(r, "customer_managed_key")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "customer_managed_key",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"customer_managed_key { key_vault_key_id = ... }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-096: PostgreSQL server without SSL enforcement
// ---------------------------------------------------------------------------

type postgresNoSSL struct{}

func (postgresNoSSL) ID() string { return "AEGIS-AZURE-096" }
func (postgresNoSSL) Title() string {
	return "PostgreSQL server without SSL enforcement"
}
func (postgresNoSSL) Description() string {
	return "azurerm_postgresql_server with ssl_enforcement_enabled = false " +
		"permits plaintext database connections. Enforce SSL."
}
func (postgresNoSSL) Severity() ir.Severity { return ir.SeverityHigh }

func (postgresNoSSL) AppliesTo(resType string) bool {
	return resType == "azurerm_postgresql_server" ||
		resType == "azurerm_postgresql_flexible_server"
}

func (s postgresNoSSL) Check(r ir.Resource) []ir.Finding {
	ssl, span, present, known := getBool(r, "ssl_enforcement_enabled")
	if !present || !known {
		return nil
	}
	if ssl {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "ssl_enforcement_enabled", span,
		"false", "ssl_enforcement_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-097: MySQL server without SSL enforcement
// ---------------------------------------------------------------------------

type mysqlNoSSL struct{}

func (mysqlNoSSL) ID() string { return "AEGIS-AZURE-097" }
func (mysqlNoSSL) Title() string {
	return "MySQL server without SSL enforcement"
}
func (mysqlNoSSL) Description() string {
	return "azurerm_mysql_server with ssl_enforcement_enabled = false " +
		"permits plaintext database connections. Enforce SSL."
}
func (mysqlNoSSL) Severity() ir.Severity { return ir.SeverityHigh }

func (mysqlNoSSL) AppliesTo(resType string) bool {
	return resType == "azurerm_mysql_server" ||
		resType == "azurerm_mysql_flexible_server"
}

func (s mysqlNoSSL) Check(r ir.Resource) []ir.Finding {
	ssl, span, present, known := getBool(r, "ssl_enforcement_enabled")
	if !present || !known {
		return nil
	}
	if ssl {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "ssl_enforcement_enabled", span,
		"false", "ssl_enforcement_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-098: MariaDB server without SSL enforcement
// ---------------------------------------------------------------------------

type mariadbNoSSL struct{}

func (mariadbNoSSL) ID() string { return "AEGIS-AZURE-098" }
func (mariadbNoSSL) Title() string {
	return "MariaDB server without SSL enforcement"
}
func (mariadbNoSSL) Description() string {
	return "azurerm_mariadb_server with ssl_enforcement_enabled = false " +
		"permits plaintext database connections. Enforce SSL."
}
func (mariadbNoSSL) Severity() ir.Severity { return ir.SeverityHigh }

func (mariadbNoSSL) AppliesTo(resType string) bool {
	return resType == "azurerm_mariadb_server"
}

func (s mariadbNoSSL) Check(r ir.Resource) []ir.Finding {
	ssl, span, present, known := getBool(r, "ssl_enforcement_enabled")
	if !present || !known {
		return nil
	}
	if ssl {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "ssl_enforcement_enabled", span,
		"false", "ssl_enforcement_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-099: Front Door without WAF policy
// ---------------------------------------------------------------------------

type frontdoorNoWAF struct{}

func (frontdoorNoWAF) ID() string { return "AEGIS-AZURE-099" }
func (frontdoorNoWAF) Title() string {
	return "Front Door without WAF policy"
}
func (frontdoorNoWAF) Description() string {
	return "azurerm_frontdoor without frontend_endpoint web_application_firewall_policy_link " +
		"lacks WAF protection. Associate a WAF policy."
}
func (frontdoorNoWAF) Severity() ir.Severity { return ir.SeverityMedium }

func (frontdoorNoWAF) AppliesTo(resType string) bool {
	return resType == "azurerm_frontdoor"
}

func (s frontdoorNoWAF) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "frontend_endpoint")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	for _, blk := range blks {
		if _, _, wp, _ := blockString(blk, "web_application_firewall_policy_link_id"); wp {
			return nil
		}
	}
	return []ir.Finding{mkFinding(s, r, "frontend_endpoint.web_application_firewall_policy_link_id",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"web_application_firewall_policy_link_id = azurerm_frontdoor_firewall_policy.example.id")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-100: Traffic Manager without HTTPS monitoring
// ---------------------------------------------------------------------------

type trafficMgrNoHTTPS struct{}

func (trafficMgrNoHTTPS) ID() string { return "AEGIS-AZURE-100" }
func (trafficMgrNoHTTPS) Title() string {
	return "Traffic Manager profile with HTTP monitoring"
}
func (trafficMgrNoHTTPS) Description() string {
	return "azurerm_traffic_manager_profile monitor_config with protocol = \"HTTP\" " +
		"health-checks over plaintext. Use HTTPS monitoring."
}
func (trafficMgrNoHTTPS) Severity() ir.Severity { return ir.SeverityLow }

func (trafficMgrNoHTTPS) AppliesTo(resType string) bool {
	return resType == "azurerm_traffic_manager_profile"
}

func (s trafficMgrNoHTTPS) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "monitor_config")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	proto, span, pp, pk := blockString(blks[0], "protocol")
	if !pp || !pk {
		return nil
	}
	if strings.EqualFold(proto, "HTTPS") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "monitor_config.protocol", span,
		proto, "protocol = \"HTTPS\"")}
}
