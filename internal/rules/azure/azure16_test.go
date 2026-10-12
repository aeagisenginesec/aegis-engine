package azure

import (
	"strconv"
	"testing"

	"aegis/internal/ir"
)

// Pack registration: Azure16Rules must be wired into Rules() in ID order.
func TestAzure16RegisteredInIDOrder(t *testing.T) {
	rules := Rules()
	idx := map[string]int{}
	for i, r := range rules {
		idx[r.ID()] = i
	}
	// 206,213 removed as post-audit duplicates.
	want := []int{207, 208, 209, 210, 211, 212, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225}
	for i, n := range want {
		id := "AEGIS-AZURE-" + strconv.Itoa(n)
		pos, ok := idx[id]
		if !ok {
			t.Fatalf("rule %s not registered", id)
		}
		if i > 0 {
			prev := "AEGIS-AZURE-" + strconv.Itoa(want[i-1])
			if idx[prev] != pos-1 {
				t.Fatalf("rules out of order: %s at %d, %s at %d", prev, idx[prev], id, pos)
			}
		}
	}
}

func siteCfg(pairs ...any) map[string]ir.Value {
	return map[string]ir.Value{"site_config": blks(2, blk(pairs...))}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-206: SQL server below TLS 1.2
// ---------------------------------------------------------------------------

func TestAZURE025(t *testing.T) {
	id := "AEGIS-AZURE-025"
	mustFinding(t, runRule(sqlServerWeakTLS{}, res("azurerm_mssql_server", "s", map[string]ir.Value{"minimum_tls_version": ks("1.0", 3)})), id)
	r := res("azurerm_mssql_server", "s", map[string]ir.Value{"minimum_tls_version": ks("1.2", 3)})
	if f := runRule(sqlServerWeakTLS{}, r); len(f) != 0 {
		t.Fatalf("TLS 1.2 must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-207/208: SQL firewall rule open to the world
// ---------------------------------------------------------------------------

func TestAZURE207_208(t *testing.T) {
	for _, c := range []struct {
		rule ir.Rule
		id   string
		typ  string
	}{
		{mssqlFirewallWorldOpen{}, "AEGIS-AZURE-207", "azurerm_mssql_firewall_rule"},
		{sqlFirewallOpenLegacy{}, "AEGIS-AZURE-208", "azurerm_sql_firewall_rule"},
	} {
		r := res(c.typ, "f", map[string]ir.Value{
			"start_ip_address": ks("0.0.0.0", 3),
			"end_ip_address":   ks("255.255.255.255", 4),
		})
		f := mustFinding(t, runRule(c.rule, r), c.id)
		if f.Severity != ir.SeverityHigh {
			t.Fatalf("%s: wrong severity %s", c.id, f.Severity)
		}
		// "Allow Azure services" (0.0.0.0-0.0.0.0) must NOT fire
		r2 := res(c.typ, "f", map[string]ir.Value{
			"start_ip_address": ks("0.0.0.0", 3),
			"end_ip_address":   ks("0.0.0.0", 4),
		})
		if f := runRule(c.rule, r2); len(f) != 0 {
			t.Fatalf("%s: azure-services rule must not fire", c.id)
		}
		// Restricted range must NOT fire
		r3 := res(c.typ, "f", map[string]ir.Value{
			"start_ip_address": ks("10.0.0.1", 3),
			"end_ip_address":   ks("10.0.0.5", 4),
		})
		if f := runRule(c.rule, r3); len(f) != 0 {
			t.Fatalf("%s: restricted range must not fire", c.id)
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-209: SQL Managed Instance with public endpoint
// ---------------------------------------------------------------------------

func TestAZURE209(t *testing.T) {
	id := "AEGIS-AZURE-209"
	mustFinding(t, runRule(mssqlMIPublicEndpoint{}, res("azurerm_mssql_managed_instance", "m", map[string]ir.Value{"public_data_endpoint_enabled": kv(true, 3)})), id)
	if f := runRule(mssqlMIPublicEndpoint{}, res("azurerm_mssql_managed_instance", "m", map[string]ir.Value{"public_data_endpoint_enabled": kv(false, 3)})); len(f) != 0 {
		t.Fatalf("disabled must not fire, got %d", len(f))
	}
	if f := runRule(mssqlMIPublicEndpoint{}, res("azurerm_mssql_managed_instance", "m", nil)); len(f) != 0 {
		t.Fatalf("absent (default false) must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-210: SQL Managed Instance below TLS 1.2
// ---------------------------------------------------------------------------

func TestAZURE210(t *testing.T) {
	id := "AEGIS-AZURE-210"
	mustFinding(t, runRule(mssqlMIMinTLS{}, res("azurerm_mssql_managed_instance", "m", map[string]ir.Value{"minimum_tls_version": ks("1.1", 3)})), id)
	if f := runRule(mssqlMIMinTLS{}, res("azurerm_mssql_managed_instance", "m", map[string]ir.Value{"minimum_tls_version": ks("1.2", 3)})); len(f) != 0 {
		t.Fatalf("TLS 1.2 must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-211..215: App Service family
// ---------------------------------------------------------------------------

func TestAZURE211_FTPS(t *testing.T) {
	id := "AEGIS-AZURE-211"
	mustFinding(t, runRule(appServiceFTPS{}, res("azurerm_app_service", "a", siteCfg())), id)
	mustFinding(t, runRule(appServiceFTPS{}, res("azurerm_app_service", "a", siteCfg("ftps_state", ks("AllAllowed", 3)))), id)
	r := res("azurerm_app_service", "a", siteCfg("ftps_state", ks("Disabled", 3)))
	if f := runRule(appServiceFTPS{}, r); len(f) != 0 {
		t.Fatalf("Disabled must not fire, got %d", len(f))
	}
}

func TestAZURE212_HTTP2(t *testing.T) {
	id := "AEGIS-AZURE-212"
	mustFinding(t, runRule(appServiceNoHTTP2{}, res("azurerm_app_service", "a", siteCfg())), id)
	r := res("azurerm_app_service", "a", siteCfg("http2_enabled", kv(true, 3)))
	if f := runRule(appServiceNoHTTP2{}, r); len(f) != 0 {
		t.Fatalf("enabled must not fire, got %d", len(f))
	}
}

func TestAZURE012_MinTLS(t *testing.T) {
	id := "AEGIS-AZURE-012"
	f := mustFinding(t, runRule(appServiceWeakTLS{}, res("azurerm_app_service", "a", siteCfg("min_tls_version", ks("1.0", 3)))), id)
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	r := res("azurerm_app_service", "a", siteCfg("min_tls_version", ks("1.2", 3)))
	if f := runRule(appServiceWeakTLS{}, r); len(f) != 0 {
		t.Fatalf("TLS 1.2 must not fire, got %d", len(f))
	}
	if f := runRule(appServiceWeakTLS{}, res("azurerm_app_service", "a", siteCfg())); len(f) != 0 {
		t.Fatalf("absent must not fire, got %d", len(f))
	}
}

func TestAZURE214_IPRestrict(t *testing.T) {
	id := "AEGIS-AZURE-214"
	mustFinding(t, runRule(appServiceNoIPRestrict{}, res("azurerm_app_service", "a", siteCfg())), id)
	r := res("azurerm_app_service", "a", map[string]ir.Value{
		"site_config": blks(2, blk("ip_restriction", blks(3, blk("ip_address", ks("10.0.0.0/8", 4))))),
	})
	if f := runRule(appServiceNoIPRestrict{}, r); len(f) != 0 {
		t.Fatalf("restricted must not fire, got %d", len(f))
	}
}

func TestAZURE215_ClientCert(t *testing.T) {
	id := "AEGIS-AZURE-215"
	mustFinding(t, runRule(appServiceNoClientCert{}, res("azurerm_app_service", "a", nil)), id)
	r := res("azurerm_app_service", "a", map[string]ir.Value{"client_cert_enabled": kv(true, 3)})
	if f := runRule(appServiceNoClientCert{}, r); len(f) != 0 {
		t.Fatalf("enabled must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-216/224: App Service slots
// ---------------------------------------------------------------------------

func TestAZURE216_224(t *testing.T) {
	mustFinding(t, runRule(appServiceSlotNoHTTPS{}, res("azurerm_app_service_slot", "s", nil)), "AEGIS-AZURE-216")
	r := res("azurerm_app_service_slot", "s", map[string]ir.Value{"https_only": kv(true, 3)})
	if f := runRule(appServiceSlotNoHTTPS{}, r); len(f) != 0 {
		t.Fatalf("216: https_only must not fire")
	}
	mustFinding(t, runRule(appServiceSlotNoIPRestrict{}, res("azurerm_app_service_slot", "s", siteCfg())), "AEGIS-AZURE-224")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-217..219: Windows Web App family
// ---------------------------------------------------------------------------

func TestAZURE217_219(t *testing.T) {
	mustFinding(t, runRule(windowsWebAppFTPS{}, res("azurerm_windows_web_app", "w", siteCfg())), "AEGIS-AZURE-217")
	mustFinding(t, runRule(windowsWebAppMinTLS{}, res("azurerm_windows_web_app", "w", siteCfg("minimum_tls_version", ks("1.0", 3)))), "AEGIS-AZURE-218")
	mustFinding(t, runRule(windowsWebAppNoIPRestrict{}, res("azurerm_windows_web_app", "w", siteCfg())), "AEGIS-AZURE-219")
	r := res("azurerm_windows_web_app", "w", siteCfg("minimum_tls_version", ks("1.2", 3), "ftps_state", ks("Disabled", 3)))
	if f := runRule(windowsWebAppFTPS{}, r); len(f) != 0 {
		t.Fatalf("217: hardened must not fire")
	}
	if f := runRule(windowsWebAppMinTLS{}, r); len(f) != 0 {
		t.Fatalf("218: hardened must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-220..222: Linux Web App family
// ---------------------------------------------------------------------------

func TestAZURE220_222(t *testing.T) {
	mustFinding(t, runRule(linuxWebAppFTPS{}, res("azurerm_linux_web_app", "l", siteCfg())), "AEGIS-AZURE-220")
	mustFinding(t, runRule(linuxWebAppMinTLS{}, res("azurerm_linux_web_app", "l", siteCfg("minimum_tls_version", ks("1.1", 3)))), "AEGIS-AZURE-221")
	mustFinding(t, runRule(linuxWebAppNoIPRestrict{}, res("azurerm_linux_web_app", "l", siteCfg())), "AEGIS-AZURE-222")
	r := res("azurerm_linux_web_app", "l", siteCfg("min_tls_version", ks("1.2", 3), "ftps_state", ks("Disabled", 3)))
	if f := runRule(linuxWebAppMinTLS{}, r); len(f) != 0 {
		t.Fatalf("221: hardened must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-223: App Service without VNet integration
// ---------------------------------------------------------------------------

func TestAZURE223(t *testing.T) {
	id := "AEGIS-AZURE-223"
	for _, typ := range []string{"azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app"} {
		mustFinding(t, runRule(appServiceNoVNet{}, res(typ, "a", nil)), id)
		r := res(typ, "a", map[string]ir.Value{"virtual_network_subnet_id": ks("/subscriptions/x/subnets/s", 3)})
		if f := runRule(appServiceNoVNet{}, r); len(f) != 0 {
			t.Fatalf("%s: integrated must not fire", typ)
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-225: SQL server without Entra ID administrator
// ---------------------------------------------------------------------------

func TestAZURE225(t *testing.T) {
	id := "AEGIS-AZURE-225"
	mustFinding(t, runRule(mssqlNoAADAdmin{}, res("azurerm_mssql_server", "s", nil)), id)
	r := res("azurerm_mssql_server", "s", map[string]ir.Value{
		"azuread_administrator": blks(3, blk("login_username", ks("admin", 4))),
	})
	if f := runRule(mssqlNoAADAdmin{}, r); len(f) != 0 {
		t.Fatalf("aad admin present must not fire, got %d", len(f))
	}
}
