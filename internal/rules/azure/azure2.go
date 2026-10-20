// Package azure — extended rule pack (AEGIS-AZURE-006..025).
//
// Same unknown-value contract as the base pack: a present-but-unresolved
// attribute yields NO finding. Absent attributes are evaluated against the
// documented insecure default per rule; rules that fire on absence say so
// explicitly. Rules never panic on unexpected shapes.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure2Rules returns the extended Azure rules in ID order.
func Azure2Rules() []ir.Rule {
	return []ir.Rule{
		storagePublicNetworkAccess{}, // AEGIS-AZURE-006
		nsgOpenSensitivePort{},       // AEGIS-AZURE-010
		appServiceNoHTTPSOnly{},      // AEGIS-AZURE-011
		appServiceWeakTLS{},          // AEGIS-AZURE-012
		cosmosNoBackupPolicy{},       // AEGIS-AZURE-013
		aksNoRBAC{},                  // AEGIS-AZURE-014
		aksNoNetworkPolicy{},         // AEGIS-AZURE-015
		acrAdminEnabled{},            // AEGIS-AZURE-016
		monitorLogNoRetention{},      // AEGIS-AZURE-017
		sqlDBNoTDE{},                 // AEGIS-AZURE-018
		redisNonSSLPort{},            // AEGIS-AZURE-019
		redisWeakTLS{},               // AEGIS-AZURE-020
		storageNetworkRulesOpen{},    // AEGIS-AZURE-021
		dbNoSSLEnforcement{},         // AEGIS-AZURE-022
		appGatewayNoWAF{},            // AEGIS-AZURE-023
		vmPasswordAuth{},             // AEGIS-AZURE-024
	}
}

// getBlocks returns nested blocks for an attribute: []Value of
// map[string]Value (a lone map is also accepted). present=false when the
// key is absent; known=false when unresolved or not a block shape.
func getBlocks(r ir.Resource, name string) (blks []map[string]ir.Value, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return nil, ir.Span{}, false, false
	}
	if !v.Known {
		return nil, v.Span, true, false
	}
	if m, ok := v.AsMap(); ok {
		return []map[string]ir.Value{m}, v.Span, true, true
	}
	l, ok := v.AsList()
	if !ok {
		return nil, v.Span, true, false
	}
	out := make([]map[string]ir.Value, 0, len(l))
	for _, item := range l {
		m, ok := item.AsMap()
		if !ok {
			continue // unexpected shape: skip defensively
		}
		out = append(out, m)
	}
	return out, v.Span, true, true
}

// blockList extracts a nested block list from a block map.
func blockList(m map[string]ir.Value, name string) []map[string]ir.Value {
	v, ok := m[name]
	if !ok || !v.Known {
		return nil
	}
	if single, ok := v.AsMap(); ok {
		return []map[string]ir.Value{single}
	}
	l, ok := v.AsList()
	if !ok {
		return nil
	}
	out := make([]map[string]ir.Value, 0, len(l))
	for _, item := range l {
		if bm, ok := item.AsMap(); ok {
			out = append(out, bm)
		}
	}
	return out
}

// blockString extracts a string from a block map (tri-state).
func blockString(m map[string]ir.Value, name string) (string, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return "", ir.Span{}, false, false
	}
	s, kok := v.AsString()
	return s, v.Span, true, kok
}

// blockBool extracts a bool from a block map (tri-state).
func blockBool(m map[string]ir.Value, name string) (bool, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	b, kok := v.AsBool()
	return b, v.Span, true, kok
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-006: Storage account with public network access
// ---------------------------------------------------------------------------

type storagePublicNetworkAccess struct{}

func (storagePublicNetworkAccess) ID() string { return "AEGIS-AZURE-006" }
func (storagePublicNetworkAccess) Title() string {
	return "Storage account with public network access"
}
func (storagePublicNetworkAccess) Description() string {
	return "azurerm_storage_account with public_network_access_enabled " +
		"exposes the storage endpoint to the internet. Disable it and use " +
		"private endpoints instead."
}
func (storagePublicNetworkAccess) Severity() ir.Severity { return ir.SeverityHigh }

func (storagePublicNetworkAccess) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storagePublicNetworkAccess) Check(r ir.Resource) []ir.Finding {
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
// AEGIS-AZURE-007: Key Vault without firewall

// ---------------------------------------------------------------------------
// AEGIS-AZURE-010: NSG rule open to the internet on a sensitive port
// ---------------------------------------------------------------------------

type nsgOpenSensitivePort struct{}

func (nsgOpenSensitivePort) ID() string { return "AEGIS-AZURE-010" }
func (nsgOpenSensitivePort) Title() string {
	return "NSG rule open to the internet on a sensitive port"
}
func (nsgOpenSensitivePort) Description() string {
	return "An inbound Allow NSG rule with an internet source targeting a " +
		"sensitive port (SSH, RDP, database ports) exposes a high-value " +
		"service directly to attackers."
}
func (nsgOpenSensitivePort) Severity() ir.Severity { return ir.SeverityMedium }

func (nsgOpenSensitivePort) AppliesTo(resType string) bool {
	return resType == "azurerm_network_security_rule"
}

// sensitivePorts are destination ports whose internet exposure is critical.
var sensitivePorts = map[string]bool{
	"22": true, "3389": true, "1433": true, "3306": true,
	"5432": true, "6379": true, "27017": true, "5985": true, "5986": true,
}

func isSensitivePort(p string) bool {
	p = strings.TrimSpace(p)
	if sensitivePorts[p] {
		return true
	}
	// Port ranges like "22-25": check the start port.
	if idx := strings.Index(p, "-"); idx > 0 {
		return sensitivePorts[strings.TrimSpace(p[:idx])]
	}
	return false
}

func (s nsgOpenSensitivePort) Check(r ir.Resource) []ir.Finding {
	dir, _, dpresent, dknown := getString(r, "direction")
	access, _, apresent, aknown := getString(r, "access")
	if !dpresent || !dknown || !apresent || !aknown {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(dir), "Inbound") {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(access), "Allow") {
		return nil
	}
	// Source must be open.
	open := false
	if pfx, _, present, known := getString(r, "source_address_prefix"); present {
		if !known {
			return nil
		}
		open = isOpenSource(pfx)
	} else if pfxs, _, ok := getStringList(r, "source_address_prefixes"); ok {
		for _, pfx := range pfxs {
			if isOpenSource(pfx) {
				open = true
				break
			}
		}
	} else {
		return nil // source absent or unresolved: cannot decide
	}
	if !open {
		return nil
	}
	// Destination port must be sensitive.
	if port, span, present, known := getString(r, "destination_port_range"); present {
		if !known {
			return nil
		}
		if strings.TrimSpace(port) == "*" {
			return []ir.Finding{mkFinding(s, r, "destination_port_range", span,
				"* from the internet", "restricted destination port range")}
		}
		if isSensitivePort(port) {
			return []ir.Finding{mkFinding(s, r, "destination_port_range", span,
				port+" from the internet", "restricted destination port range")}
		}
		return nil
	}
	if ports, span, ok := getStringList(r, "destination_port_ranges"); ok {
		for _, port := range ports {
			if strings.TrimSpace(port) == "*" || isSensitivePort(port) {
				return []ir.Finding{mkFinding(s, r, "destination_port_ranges", span,
					port+" from the internet", "restricted destination port ranges")}
			}
		}
		return nil
	}
	return nil // destination port absent or unresolved: cannot decide
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-011: App Service without HTTPS-only
// ---------------------------------------------------------------------------

type appServiceNoHTTPSOnly struct{}

func (appServiceNoHTTPSOnly) ID() string { return "AEGIS-AZURE-011" }
func (appServiceNoHTTPSOnly) Title() string {
	return "App Service without HTTPS-only"
}
func (appServiceNoHTTPSOnly) Description() string {
	return "App Service with https_only = false serves traffic over " +
		"plaintext HTTP. Enable https_only to force TLS."
}
func (appServiceNoHTTPSOnly) Severity() ir.Severity { return ir.SeverityHigh }

func (appServiceNoHTTPSOnly) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service" ||
		resType == "azurerm_linux_web_app" ||
		resType == "azurerm_windows_web_app"
}

func (s appServiceNoHTTPSOnly) Check(r ir.Resource) []ir.Finding {
	https, span, present, known := getBool(r, "https_only")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if https {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "https_only", span,
		"false", "https_only = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-012: App Service below TLS 1.2
// ---------------------------------------------------------------------------

type appServiceWeakTLS struct{}

func (appServiceWeakTLS) ID() string { return "AEGIS-AZURE-012" }
func (appServiceWeakTLS) Title() string {
	return "App Service below TLS 1.2"
}
func (appServiceWeakTLS) Description() string {
	return "App Service should enforce TLS 1.2 as the minimum version " +
		"via site_config.min_tls_version to protect data in transit."
}
func (appServiceWeakTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (appServiceWeakTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service" ||
		resType == "azurerm_linux_web_app" ||
		resType == "azurerm_windows_web_app"
}

func (s appServiceWeakTLS) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present || !known || len(blks) == 0 {
		return nil // site_config absent or unresolved: cannot decide
	}
	ver, span, vpresent, vknown := blockString(blks[0], "min_tls_version")
	if !vpresent || !vknown {
		return nil // absent or unresolved: cannot decide
	}
	if strings.EqualFold(strings.TrimSpace(ver), "1.2") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "site_config.min_tls_version", span,
		ver, "min_tls_version = \"1.2\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-013: CosmosDB account without explicit backup policy
// ---------------------------------------------------------------------------

type cosmosNoBackupPolicy struct{}

func (cosmosNoBackupPolicy) ID() string { return "AEGIS-AZURE-013" }
func (cosmosNoBackupPolicy) Title() string {
	return "CosmosDB account without explicit backup policy"
}
func (cosmosNoBackupPolicy) Description() string {
	return "azurerm_cosmosdb_account with no backup block relies on the " +
		"implicit periodic default. Declare an explicit backup policy " +
		"(preferably continuous) so retention is a conscious choice."
}
func (cosmosNoBackupPolicy) Severity() ir.Severity { return ir.SeverityMedium }

func (cosmosNoBackupPolicy) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosNoBackupPolicy) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "backup")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil // explicit backup policy
	}
	// Absent: no explicit backup policy. Documented insecure default.
	return []ir.Finding{mkFinding(s, r, "backup", r.Span,
		"absent", "backup { type = \"Continuous\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-014: AKS cluster without RBAC
// ---------------------------------------------------------------------------

type aksNoRBAC struct{}

func (aksNoRBAC) ID() string { return "AEGIS-AZURE-014" }
func (aksNoRBAC) Title() string {
	return "AKS cluster without RBAC"
}
func (aksNoRBAC) Description() string {
	return "azurerm_kubernetes_cluster with " +
		"role_based_access_control_enabled = false disables Kubernetes " +
		"RBAC, giving every credential full cluster access."
}
func (aksNoRBAC) Severity() ir.Severity { return ir.SeverityHigh }

func (aksNoRBAC) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoRBAC) Check(r ir.Resource) []ir.Finding {
	rbac, span, present, known := getBool(r, "role_based_access_control_enabled")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if rbac {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "role_based_access_control_enabled", span,
		"false", "role_based_access_control_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-015: AKS cluster without network policy
// ---------------------------------------------------------------------------

type aksNoNetworkPolicy struct{}

func (aksNoNetworkPolicy) ID() string { return "AEGIS-AZURE-015" }
func (aksNoNetworkPolicy) Title() string {
	return "AKS cluster without network policy"
}
func (aksNoNetworkPolicy) Description() string {
	return "azurerm_kubernetes_cluster with no network_policy in " +
		"network_profile allows unrestricted pod-to-pod traffic. " +
		"Enable a network policy engine (azure or calico)."
}
func (aksNoNetworkPolicy) Severity() ir.Severity { return ir.SeverityHigh }

func (aksNoNetworkPolicy) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoNetworkPolicy) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "network_profile")
	if !present {
		// No network profile at all: network policy cannot be enabled.
		// Documented insecure default.
		return []ir.Finding{mkFinding(s, r, "network_profile", r.Span,
			"absent", "network_profile { network_policy = \"azure\" }")}
	}
	if !known || len(blks) == 0 {
		return nil // unresolved: cannot decide
	}
	pol, span, ppresent, pknown := blockString(blks[0], "network_policy")
	if !ppresent {
		return []ir.Finding{mkFinding(s, r, "network_profile.network_policy", blks[0]["network_policy"].Span,
			"absent", "network_policy = \"azure\"")}
	}
	if !pknown {
		return nil // unresolved: cannot decide
	}
	if strings.TrimSpace(pol) == "" {
		return []ir.Finding{mkFinding(s, r, "network_profile.network_policy", span,
			"empty", "network_policy = \"azure\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-016: Container Registry with admin user enabled
// ---------------------------------------------------------------------------

type acrAdminEnabled struct{}

func (acrAdminEnabled) ID() string { return "AEGIS-AZURE-016" }
func (acrAdminEnabled) Title() string {
	return "Container Registry with admin user enabled"
}
func (acrAdminEnabled) Description() string {
	return "azurerm_container_registry with admin_enabled = true exposes a " +
		"long-lived admin credential. Use Azure AD / managed identity " +
		"authentication instead."
}
func (acrAdminEnabled) Severity() ir.Severity { return ir.SeverityHigh }

func (acrAdminEnabled) AppliesTo(resType string) bool {
	return resType == "azurerm_container_registry"
}

func (s acrAdminEnabled) Check(r ir.Resource) []ir.Finding {
	admin, span, present, known := getBool(r, "admin_enabled")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !admin {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "admin_enabled", span,
		"true", "admin_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-017: Monitor log profile without retention
// ---------------------------------------------------------------------------

type monitorLogNoRetention struct{}

func (monitorLogNoRetention) ID() string { return "AEGIS-AZURE-017" }
func (monitorLogNoRetention) Title() string {
	return "Monitor log profile without retention"
}
func (monitorLogNoRetention) Description() string {
	return "azurerm_monitor_log_profile with no retention_policy, or with " +
		"retention disabled, keeps no durable audit trail of control-plane " +
		"activity."
}
func (monitorLogNoRetention) Severity() ir.Severity { return ir.SeverityMedium }

func (monitorLogNoRetention) AppliesTo(resType string) bool {
	return resType == "azurerm_monitor_log_profile"
}

func (s monitorLogNoRetention) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "retention_policy")
	if !present {
		return []ir.Finding{mkFinding(s, r, "retention_policy", r.Span,
			"absent", "retention_policy { enabled = true, days = 365 }")}
	}
	if !known || len(blks) == 0 {
		return nil // unresolved: cannot decide
	}
	en, span, epresent, eknown := blockBool(blks[0], "enabled")
	if !epresent || !eknown {
		return nil // unresolved: cannot decide
	}
	if !en {
		return []ir.Finding{mkFinding(s, r, "retention_policy.enabled", span,
			"false", "enabled = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-018: SQL database without transparent data encryption
// ---------------------------------------------------------------------------

type sqlDBNoTDE struct{}

func (sqlDBNoTDE) ID() string { return "AEGIS-AZURE-018" }
func (sqlDBNoTDE) Title() string {
	return "SQL database without transparent data encryption"
}
func (sqlDBNoTDE) Description() string {
	return "azurerm_mssql_database with transparent_data_encryption_enabled " +
		"= false stores data files unencrypted at rest."
}
func (sqlDBNoTDE) Severity() ir.Severity { return ir.SeverityHigh }

func (sqlDBNoTDE) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_database"
}

func (s sqlDBNoTDE) Check(r ir.Resource) []ir.Finding {
	tde, span, present, known := getBool(r, "transparent_data_encryption_enabled")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if tde {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "transparent_data_encryption_enabled", span,
		"false", "transparent_data_encryption_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-019: Redis cache with non-SSL port enabled
// ---------------------------------------------------------------------------

type redisNonSSLPort struct{}

func (redisNonSSLPort) ID() string { return "AEGIS-AZURE-019" }
func (redisNonSSLPort) Title() string {
	return "Redis cache with non-SSL port enabled"
}
func (redisNonSSLPort) Description() string {
	return "azurerm_redis_cache with enable_non_ssl_port = true accepts " +
		"plaintext Redis connections, exposing credentials and data in " +
		"transit."
}
func (redisNonSSLPort) Severity() ir.Severity { return ir.SeverityHigh }

func (redisNonSSLPort) AppliesTo(resType string) bool {
	return resType == "azurerm_redis_cache"
}

func (s redisNonSSLPort) Check(r ir.Resource) []ir.Finding {
	plain, span, present, known := getBool(r, "enable_non_ssl_port")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !plain {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "enable_non_ssl_port", span,
		"true", "enable_non_ssl_port = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-020: Redis cache below TLS 1.2
// ---------------------------------------------------------------------------

type redisWeakTLS struct{}

func (redisWeakTLS) ID() string { return "AEGIS-AZURE-020" }
func (redisWeakTLS) Title() string {
	return "Redis cache below TLS 1.2"
}
func (redisWeakTLS) Description() string {
	return "azurerm_redis_cache should enforce TLS 1.2 via " +
		"minimum_tls_version to protect data in transit."
}
func (redisWeakTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (redisWeakTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_redis_cache"
}

func (s redisWeakTLS) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "minimum_tls_version")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if strings.EqualFold(strings.TrimSpace(ver), "1.2") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "minimum_tls_version", span,
		ver, "minimum_tls_version = \"1.2\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-021: Storage account network rules allow all
// ---------------------------------------------------------------------------

type storageNetworkRulesOpen struct{}

func (storageNetworkRulesOpen) ID() string { return "AEGIS-AZURE-021" }
func (storageNetworkRulesOpen) Title() string {
	return "Storage account network rules allow all"
}
func (storageNetworkRulesOpen) Description() string {
	return "azurerm_storage_account with network_rules.default_action = " +
		"\"Allow\" accepts storage traffic from any network. Restrict with " +
		"default_action = \"Deny\" and explicit bypass rules."
}
func (storageNetworkRulesOpen) Severity() ir.Severity { return ir.SeverityMedium }

func (storageNetworkRulesOpen) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNetworkRulesOpen) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "network_rules")
	if !present || !known || len(blks) == 0 {
		return nil // absent or unresolved: cannot decide
	}
	action, span, apresent, aknown := blockString(blks[0], "default_action")
	if !apresent || !aknown {
		return nil // unresolved: cannot decide
	}
	if strings.EqualFold(strings.TrimSpace(action), "Allow") {
		return []ir.Finding{mkFinding(s, r, "network_rules.default_action", span,
			action, "default_action = \"Deny\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-022: Database server without SSL enforcement
// ---------------------------------------------------------------------------

type dbNoSSLEnforcement struct{}

func (dbNoSSLEnforcement) ID() string { return "AEGIS-AZURE-022" }
func (dbNoSSLEnforcement) Title() string {
	return "Database server without SSL enforcement"
}
func (dbNoSSLEnforcement) Description() string {
	return "MySQL/PostgreSQL servers with ssl_enforcement_enabled = false " +
		"accept plaintext database connections, exposing credentials and " +
		"query data in transit."
}
func (dbNoSSLEnforcement) Severity() ir.Severity { return ir.SeverityHigh }

func (dbNoSSLEnforcement) AppliesTo(resType string) bool {
	return resType == "azurerm_mysql_server" ||
		resType == "azurerm_postgresql_server"
}

func (s dbNoSSLEnforcement) Check(r ir.Resource) []ir.Finding {
	ssl, span, present, known := getBool(r, "ssl_enforcement_enabled")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if ssl {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "ssl_enforcement_enabled", span,
		"false", "ssl_enforcement_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-023: Application Gateway without WAF
// ---------------------------------------------------------------------------

type appGatewayNoWAF struct{}

func (appGatewayNoWAF) ID() string { return "AEGIS-AZURE-023" }
func (appGatewayNoWAF) Title() string {
	return "Application Gateway without WAF"
}
func (appGatewayNoWAF) Description() string {
	return "azurerm_application_gateway with no waf_configuration block " +
		"has no web application firewall in front of backend services. " +
		"Enable WAF in prevention mode."
}
func (appGatewayNoWAF) Severity() ir.Severity { return ir.SeverityMedium }

func (appGatewayNoWAF) AppliesTo(resType string) bool {
	return resType == "azurerm_application_gateway"
}

func (s appGatewayNoWAF) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "waf_configuration")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil // WAF configured
	}
	// Absent: no WAF. Documented insecure default.
	return []ir.Finding{mkFinding(s, r, "waf_configuration", r.Span,
		"absent", "waf_configuration { enabled = true, firewall_mode = \"Prevention\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-024: Linux VM with password authentication
// ---------------------------------------------------------------------------

type vmPasswordAuth struct{}

func (vmPasswordAuth) ID() string { return "AEGIS-AZURE-024" }
func (vmPasswordAuth) Title() string {
	return "Linux VM with password authentication"
}
func (vmPasswordAuth) Description() string {
	return "azurerm_linux_virtual_machine with disable_password_authentication " +
		"= false allows SSH password logins, which are brute-forceable. " +
		"Use SSH keys only."
}
func (vmPasswordAuth) Severity() ir.Severity { return ir.SeverityHigh }

func (vmPasswordAuth) AppliesTo(resType string) bool {
	return resType == "azurerm_linux_virtual_machine"
}

func (s vmPasswordAuth) Check(r ir.Resource) []ir.Finding {
	dis, span, present, known := getBool(r, "disable_password_authentication")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if dis {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "disable_password_authentication", span,
		"false", "disable_password_authentication = true")}
}
