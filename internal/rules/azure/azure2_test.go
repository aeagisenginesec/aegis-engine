package azure

import (
	"testing"

	"aegis/internal/ir"
)

// blk builds a block map from key/value pairs.
func blk(pairs ...any) map[string]ir.Value {
	m := map[string]ir.Value{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1].(ir.Value)
	}
	return m
}

// blks builds a block-list value.
func blks(line int, maps ...map[string]ir.Value) ir.Value {
	vals := make([]ir.Value, len(maps))
	for i, m := range maps {
		vals[i] = ir.Value{Raw: m, Known: true, Span: spanAt(line)}
	}
	return ir.Value{Raw: vals, Known: true, Span: spanAt(line)}
}

func TestAZURE006_PublicNetworkAccessFires(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{"public_network_access_enabled": kv(true, 3)})
	mustFinding(t, runRule(storagePublicNetworkAccess{}, r), "AEGIS-AZURE-006")
}

func TestAZURE006_PrivateQuiet(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{"public_network_access_enabled": kv(false, 3)})
	if len(runRule(storagePublicNetworkAccess{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE006_UnknownQuiet(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{"public_network_access_enabled": ku(3)})
	if len(runRule(storagePublicNetworkAccess{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE007_NoFirewallFires(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{})
	mustFinding(t, runRule(keyVaultNoFirewall{}, r), "AEGIS-AZURE-007")
}

func TestAZURE007_AllowDefaultFires(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{
		"network_acls": blks(3, blk("default_action", ks("Allow", 4))),
	})
	mustFinding(t, runRule(keyVaultNoFirewall{}, r), "AEGIS-AZURE-007")
}

func TestAZURE007_DenyQuiet(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{
		"network_acls": blks(3, blk("default_action", ks("Deny", 4))),
	})
	if len(runRule(keyVaultNoFirewall{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE007_UnknownQuiet(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"network_acls": ku(3)})
	if len(runRule(keyVaultNoFirewall{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE010_OpenSSHFromInternetFires(t *testing.T) {
	r := res("azurerm_network_security_rule", "r", map[string]ir.Value{
		"direction":              ks("Inbound", 3),
		"access":                 ks("Allow", 3),
		"source_address_prefix":  ks("0.0.0.0/0", 3),
		"destination_port_range": ks("22", 3),
	})
	mustFinding(t, runRule(nsgOpenSensitivePort{}, r), "AEGIS-AZURE-010")
}

func TestAZURE010_OpenHTTQuiet(t *testing.T) {
	r := res("azurerm_network_security_rule", "r", map[string]ir.Value{
		"direction":              ks("Inbound", 3),
		"access":                 ks("Allow", 3),
		"source_address_prefix":  ks("0.0.0.0/0", 3),
		"destination_port_range": ks("80", 3),
	})
	if len(runRule(nsgOpenSensitivePort{}, r)) != 0 {
		t.Fatal("expected 0 findings for non-sensitive port")
	}
}

func TestAZURE010_UnknownQuiet(t *testing.T) {
	r := res("azurerm_network_security_rule", "r", map[string]ir.Value{
		"direction":              ks("Inbound", 3),
		"access":                 ks("Allow", 3),
		"source_address_prefix":  ku(3),
		"destination_port_range": ks("22", 3),
	})
	if len(runRule(nsgOpenSensitivePort{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown source")
	}
}

func TestAZURE011_NoHTTPSOnlyFires(t *testing.T) {
	for _, typ := range []string{"azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"} {
		r := res(typ, "a", map[string]ir.Value{"https_only": kv(false, 3)})
		mustFinding(t, runRule(appServiceNoHTTPSOnly{}, r), "AEGIS-AZURE-011")
	}
}

func TestAZURE011_HTTPSOnlyQuiet(t *testing.T) {
	r := res("azurerm_linux_web_app", "a", map[string]ir.Value{"https_only": kv(true, 3)})
	if len(runRule(appServiceNoHTTPSOnly{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE011_UnknownQuiet(t *testing.T) {
	r := res("azurerm_app_service", "a", map[string]ir.Value{"https_only": ku(3)})
	if len(runRule(appServiceNoHTTPSOnly{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE012_WeakTLSFires(t *testing.T) {
	r := res("azurerm_linux_web_app", "a", map[string]ir.Value{
		"site_config": blks(3, blk("min_tls_version", ks("1.0", 4))),
	})
	mustFinding(t, runRule(appServiceWeakTLS{}, r), "AEGIS-AZURE-012")
}

func TestAZURE012_TLS12Quiet(t *testing.T) {
	r := res("azurerm_linux_web_app", "a", map[string]ir.Value{
		"site_config": blks(3, blk("min_tls_version", ks("1.2", 4))),
	})
	if len(runRule(appServiceWeakTLS{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE012_UnknownQuiet(t *testing.T) {
	r := res("azurerm_app_service", "a", map[string]ir.Value{
		"site_config": blks(3, blk("min_tls_version", ku(4))),
	})
	if len(runRule(appServiceWeakTLS{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE013_NoBackupFires(t *testing.T) {
	r := res("azurerm_cosmosdb_account", "c", map[string]ir.Value{})
	mustFinding(t, runRule(cosmosNoBackupPolicy{}, r), "AEGIS-AZURE-013")
}

func TestAZURE013_BackupQuiet(t *testing.T) {
	r := res("azurerm_cosmosdb_account", "c", map[string]ir.Value{
		"backup": blks(3, blk("type", ks("Continuous", 4))),
	})
	if len(runRule(cosmosNoBackupPolicy{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE013_UnknownQuiet(t *testing.T) {
	r := res("azurerm_cosmosdb_account", "c", map[string]ir.Value{"backup": ku(3)})
	if len(runRule(cosmosNoBackupPolicy{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE014_NoRBACFires(t *testing.T) {
	r := res("azurerm_kubernetes_cluster", "k", map[string]ir.Value{"role_based_access_control_enabled": kv(false, 3)})
	mustFinding(t, runRule(aksNoRBAC{}, r), "AEGIS-AZURE-014")
}

func TestAZURE014_RBACQuiet(t *testing.T) {
	r := res("azurerm_kubernetes_cluster", "k", map[string]ir.Value{"role_based_access_control_enabled": kv(true, 3)})
	if len(runRule(aksNoRBAC{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE014_UnknownQuiet(t *testing.T) {
	r := res("azurerm_kubernetes_cluster", "k", map[string]ir.Value{"role_based_access_control_enabled": ku(3)})
	if len(runRule(aksNoRBAC{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE015_NoNetworkProfileFires(t *testing.T) {
	r := res("azurerm_kubernetes_cluster", "k", map[string]ir.Value{})
	mustFinding(t, runRule(aksNoNetworkPolicy{}, r), "AEGIS-AZURE-015")
}

func TestAZURE015_NetworkPolicyQuiet(t *testing.T) {
	r := res("azurerm_kubernetes_cluster", "k", map[string]ir.Value{
		"network_profile": blks(3, blk("network_policy", ks("azure", 4))),
	})
	if len(runRule(aksNoNetworkPolicy{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE015_UnknownQuiet(t *testing.T) {
	r := res("azurerm_kubernetes_cluster", "k", map[string]ir.Value{"network_profile": ku(3)})
	if len(runRule(aksNoNetworkPolicy{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE016_AdminEnabledFires(t *testing.T) {
	r := res("azurerm_container_registry", "c", map[string]ir.Value{"admin_enabled": kv(true, 3)})
	mustFinding(t, runRule(acrAdminEnabled{}, r), "AEGIS-AZURE-016")
}

func TestAZURE016_AdminDisabledQuiet(t *testing.T) {
	r := res("azurerm_container_registry", "c", map[string]ir.Value{"admin_enabled": kv(false, 3)})
	if len(runRule(acrAdminEnabled{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE016_UnknownQuiet(t *testing.T) {
	r := res("azurerm_container_registry", "c", map[string]ir.Value{"admin_enabled": ku(3)})
	if len(runRule(acrAdminEnabled{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE017_NoRetentionFires(t *testing.T) {
	r := res("azurerm_monitor_log_profile", "m", map[string]ir.Value{})
	mustFinding(t, runRule(monitorLogNoRetention{}, r), "AEGIS-AZURE-017")
}

func TestAZURE017_RetentionDisabledFires(t *testing.T) {
	r := res("azurerm_monitor_log_profile", "m", map[string]ir.Value{
		"retention_policy": blks(3, blk("enabled", kv(false, 4))),
	})
	mustFinding(t, runRule(monitorLogNoRetention{}, r), "AEGIS-AZURE-017")
}

func TestAZURE017_RetentionQuiet(t *testing.T) {
	r := res("azurerm_monitor_log_profile", "m", map[string]ir.Value{
		"retention_policy": blks(3, blk("enabled", kv(true, 4), "days", ks("365", 4))),
	})
	if len(runRule(monitorLogNoRetention{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE018_NoTDEFires(t *testing.T) {
	r := res("azurerm_mssql_database", "d", map[string]ir.Value{"transparent_data_encryption_enabled": kv(false, 3)})
	mustFinding(t, runRule(sqlDBNoTDE{}, r), "AEGIS-AZURE-018")
}

func TestAZURE018_TDEQuiet(t *testing.T) {
	r := res("azurerm_mssql_database", "d", map[string]ir.Value{"transparent_data_encryption_enabled": kv(true, 3)})
	if len(runRule(sqlDBNoTDE{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE018_UnknownQuiet(t *testing.T) {
	r := res("azurerm_mssql_database", "d", map[string]ir.Value{"transparent_data_encryption_enabled": ku(3)})
	if len(runRule(sqlDBNoTDE{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE019_NonSSLPortFires(t *testing.T) {
	r := res("azurerm_redis_cache", "r", map[string]ir.Value{"enable_non_ssl_port": kv(true, 3)})
	mustFinding(t, runRule(redisNonSSLPort{}, r), "AEGIS-AZURE-019")
}

func TestAZURE019_SSLOnlyQuiet(t *testing.T) {
	r := res("azurerm_redis_cache", "r", map[string]ir.Value{"enable_non_ssl_port": kv(false, 3)})
	if len(runRule(redisNonSSLPort{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE019_UnknownQuiet(t *testing.T) {
	r := res("azurerm_redis_cache", "r", map[string]ir.Value{"enable_non_ssl_port": ku(3)})
	if len(runRule(redisNonSSLPort{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE020_WeakTLSFires(t *testing.T) {
	r := res("azurerm_redis_cache", "r", map[string]ir.Value{"minimum_tls_version": ks("1.0", 3)})
	mustFinding(t, runRule(redisWeakTLS{}, r), "AEGIS-AZURE-020")
}

func TestAZURE020_TLS12Quiet(t *testing.T) {
	r := res("azurerm_redis_cache", "r", map[string]ir.Value{"minimum_tls_version": ks("1.2", 3)})
	if len(runRule(redisWeakTLS{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE020_UnknownQuiet(t *testing.T) {
	r := res("azurerm_redis_cache", "r", map[string]ir.Value{"minimum_tls_version": ku(3)})
	if len(runRule(redisWeakTLS{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE021_OpenNetworkRulesFires(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"network_rules": blks(3, blk("default_action", ks("Allow", 4))),
	})
	mustFinding(t, runRule(storageNetworkRulesOpen{}, r), "AEGIS-AZURE-021")
}

func TestAZURE021_DenyQuiet(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"network_rules": blks(3, blk("default_action", ks("Deny", 4))),
	})
	if len(runRule(storageNetworkRulesOpen{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE021_AbsentQuiet(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{})
	if len(runRule(storageNetworkRulesOpen{}, r)) != 0 {
		t.Fatal("expected 0 findings for absent network_rules")
	}
}

func TestAZURE022_NoSSLEnforcementFires(t *testing.T) {
	for _, typ := range []string{"azurerm_mysql_server", "azurerm_postgresql_server"} {
		r := res(typ, "d", map[string]ir.Value{"ssl_enforcement_enabled": kv(false, 3)})
		mustFinding(t, runRule(dbNoSSLEnforcement{}, r), "AEGIS-AZURE-022")
	}
}

func TestAZURE022_SSLEnforcedQuiet(t *testing.T) {
	r := res("azurerm_mysql_server", "d", map[string]ir.Value{"ssl_enforcement_enabled": kv(true, 3)})
	if len(runRule(dbNoSSLEnforcement{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE022_UnknownQuiet(t *testing.T) {
	r := res("azurerm_postgresql_server", "d", map[string]ir.Value{"ssl_enforcement_enabled": ku(3)})
	if len(runRule(dbNoSSLEnforcement{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE023_NoWAFFires(t *testing.T) {
	r := res("azurerm_application_gateway", "g", map[string]ir.Value{})
	mustFinding(t, runRule(appGatewayNoWAF{}, r), "AEGIS-AZURE-023")
}

func TestAZURE023_WAFQuiet(t *testing.T) {
	r := res("azurerm_application_gateway", "g", map[string]ir.Value{
		"waf_configuration": blks(3, blk("enabled", kv(true, 4))),
	})
	if len(runRule(appGatewayNoWAF{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE023_UnknownQuiet(t *testing.T) {
	r := res("azurerm_application_gateway", "g", map[string]ir.Value{"waf_configuration": ku(3)})
	if len(runRule(appGatewayNoWAF{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAZURE024_PasswordAuthFires(t *testing.T) {
	r := res("azurerm_linux_virtual_machine", "v", map[string]ir.Value{"disable_password_authentication": kv(false, 3)})
	mustFinding(t, runRule(vmPasswordAuth{}, r), "AEGIS-AZURE-024")
}

func TestAZURE024_KeysOnlyQuiet(t *testing.T) {
	r := res("azurerm_linux_virtual_machine", "v", map[string]ir.Value{"disable_password_authentication": kv(true, 3)})
	if len(runRule(vmPasswordAuth{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE024_UnknownQuiet(t *testing.T) {
	r := res("azurerm_linux_virtual_machine", "v", map[string]ir.Value{"disable_password_authentication": ku(3)})
	if len(runRule(vmPasswordAuth{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestAzure2Rules_IDOrder(t *testing.T) {
	rules := Azure2Rules()
	if len(rules) != 17 {
		t.Fatalf("expected 17 rules, got %d", len(rules))
	}
	// Explicit ID sequence check.
	want := []string{
		"AEGIS-AZURE-006", "AEGIS-AZURE-007",
		"AEGIS-AZURE-010", "AEGIS-AZURE-011", "AEGIS-AZURE-012", "AEGIS-AZURE-013",
		"AEGIS-AZURE-014", "AEGIS-AZURE-015", "AEGIS-AZURE-016", "AEGIS-AZURE-017",
		"AEGIS-AZURE-018", "AEGIS-AZURE-019", "AEGIS-AZURE-020", "AEGIS-AZURE-021",
		"AEGIS-AZURE-022", "AEGIS-AZURE-023", "AEGIS-AZURE-024",
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
