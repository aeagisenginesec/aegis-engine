package azure

import (
	"testing"

	"aegis/internal/ir"
)

// TestAZURE081_NoIPFilterFires verifies CosmosDB IP filtering.
func TestAZURE081_NoIPFilterFires(t *testing.T) {
	r := res("azurerm_cosmosdb_account", "c", map[string]ir.Value{})
	mustFinding(t, runRule(cosmosNoIPFilter{}, r), "AEGIS-AZURE-081")
}

func TestAZURE081_IPFilterQuiet(t *testing.T) {
	r := res("azurerm_cosmosdb_account", "c", map[string]ir.Value{"ip_range_filter": ks("203.0.113.0/24", 3)})
	if len(runRule(cosmosNoIPFilter{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE082_NoBackupFires verifies CosmosDB backup.
func TestAZURE082_NoBackupFires(t *testing.T) {
	r := res("azurerm_cosmosdb_account", "c", map[string]ir.Value{})
	mustFinding(t, runRule(cosmosNoBackup{}, r), "AEGIS-AZURE-082")
}

// TestAZURE084_PublicAccessFires verifies CosmosDB public access.
func TestAZURE084_PublicAccessFires(t *testing.T) {
	r := res("azurerm_cosmosdb_account", "c", map[string]ir.Value{"public_network_access_enabled": kv(true, 3)})
	mustFinding(t, runRule(cosmosPublicAccess{}, r), "AEGIS-AZURE-084")
}

// TestAZURE087_NoNetworkRulesFires verifies ACR network rules.
func TestAZURE087_NoNetworkRulesFires(t *testing.T) {
	r := res("azurerm_container_registry", "a", map[string]ir.Value{"sku": ks("Premium", 3)})
	mustFinding(t, runRule(acrNoNetworkRules{}, r), "AEGIS-AZURE-087")
}

func TestAZURE087_BasicSkuQuiet(t *testing.T) {
	r := res("azurerm_container_registry", "a", map[string]ir.Value{"sku": ks("Basic", 3)})
	if len(runRule(acrNoNetworkRules{}, r)) != 0 {
		t.Fatal("expected 0 findings for Basic SKU")
	}
}

// TestAZURE090_PublicAccessFires verifies ACR public access.
func TestAZURE090_PublicAccessFires(t *testing.T) {
	r := res("azurerm_container_registry", "a", map[string]ir.Value{"public_network_access_enabled": kv(true, 3)})
	mustFinding(t, runRule(acrPublicAccess{}, r), "AEGIS-AZURE-090")
}

// TestAZURE091_NoCategoriesFires verifies monitor log profile.
func TestAZURE091_NoCategoriesFires(t *testing.T) {
	r := res("azurerm_monitor_log_profile", "m", map[string]ir.Value{})
	mustFinding(t, runRule(monitorNoActivityLog{}, r), "AEGIS-AZURE-091")
}

// TestAZURE096_PostgresNoSSLFires verifies PostgreSQL SSL.
func TestAZURE096_PostgresNoSSLFires(t *testing.T) {
	r := res("azurerm_postgresql_server", "p", map[string]ir.Value{"ssl_enforcement_enabled": kv(false, 3)})
	mustFinding(t, runRule(postgresNoSSL{}, r), "AEGIS-AZURE-096")
}

func TestAZURE096_SSLQuiet(t *testing.T) {
	r := res("azurerm_postgresql_server", "p", map[string]ir.Value{"ssl_enforcement_enabled": kv(true, 3)})
	if len(runRule(postgresNoSSL{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE097_MysqlNoSSLFires verifies MySQL SSL.
func TestAZURE097_MysqlNoSSLFires(t *testing.T) {
	r := res("azurerm_mysql_server", "m", map[string]ir.Value{"ssl_enforcement_enabled": kv(false, 3)})
	mustFinding(t, runRule(mysqlNoSSL{}, r), "AEGIS-AZURE-097")
}

// TestAZURE099_NoWAFFires verifies Front Door WAF.
func TestAZURE099_NoWAFFires(t *testing.T) {
	r := res("azurerm_frontdoor", "f", map[string]ir.Value{
		"frontend_endpoint": blks(3, blk("name", ks("example", 4))),
	})
	mustFinding(t, runRule(frontdoorNoWAF{}, r), "AEGIS-AZURE-099")
}

// TestAZURE100_HTTPMonitorFires verifies Traffic Manager protocol.
func TestAZURE100_HTTPMonitorFires(t *testing.T) {
	r := res("azurerm_traffic_manager_profile", "t", map[string]ir.Value{
		"monitor_config": blks(3, blk("protocol", ks("HTTP", 4))),
	})
	mustFinding(t, runRule(trafficMgrNoHTTPS{}, r), "AEGIS-AZURE-100")
}

func TestAZURE100_HTTPSQuiet(t *testing.T) {
	r := res("azurerm_traffic_manager_profile", "t", map[string]ir.Value{
		"monitor_config": blks(3, blk("protocol", ks("HTTPS", 4))),
	})
	if len(runRule(trafficMgrNoHTTPS{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
