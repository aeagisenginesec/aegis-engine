package azure

import (
	"strings"
	"testing"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AZURE-314: SQL server administrator with weak password
// ---------------------------------------------------------------------------

func TestAZURE314_WeakFires(t *testing.T) {
	for _, pw := range []string{"Password123!", "password123", "Admin2024", "changeme", "short1!", ""} {
		r := res("azurerm_sql_server", "weak", map[string]ir.Value{
			"administrator_login_password": ks(pw, 3),
		})
		f := runRule(sqlWeakAdminPassword{}, r)
		if len(f) != 1 || f[0].RuleID != "AEGIS-AZURE-314" {
			t.Errorf("password %q: expected 314 to fire, got %+v", pw, f)
			continue
		}
		if pw != "" && (strings.Contains(f[0].Evidence.Actual, pw) || strings.Contains(f[0].Description, pw)) {
			t.Errorf("password %q: finding must never carry the password value", pw)
		}
	}
}

func TestAZURE314_StrongQuiet(t *testing.T) {
	for _, pw := range []string{"Str0ng-4c2865-Db!", "x9#Qw2!zL8$vN4&pR7", "correct-horse-battery-staple-99"} {
		r := res("azurerm_sql_server", "ok", map[string]ir.Value{
			"administrator_login_password": ks(pw, 3),
		})
		if f := runRule(sqlWeakAdminPassword{}, r); len(f) != 0 {
			t.Errorf("password %q: expected quiet, got %+v", pw, f)
		}
	}
}

func TestAZURE314_UnknownAndAbsentQuiet(t *testing.T) {
	r := res("azurerm_sql_server", "u", map[string]ir.Value{
		"administrator_login_password": ku(3),
	})
	if f := runRule(sqlWeakAdminPassword{}, r); len(f) != 0 {
		t.Fatalf("unknown password must stay quiet, got %+v", f)
	}
	r2 := res("azurerm_sql_server", "a", map[string]ir.Value{})
	if f := runRule(sqlWeakAdminPassword{}, r2); len(f) != 0 {
		t.Fatalf("absent password must stay quiet, got %+v", f)
	}
}

func TestAZURE314_AppliesToServers(t *testing.T) {
	for _, typ := range []string{
		"azurerm_sql_server", "azurerm_mssql_server",
		"azurerm_mysql_server", "azurerm_postgresql_server",
		"azurerm_mysql_flexible_server", "azurerm_postgresql_flexible_server",
	} {
		r := res(typ, "s", map[string]ir.Value{
			"administrator_login_password": ks("password123", 3),
		})
		if f := runRule(sqlWeakAdminPassword{}, r); len(f) != 1 {
			t.Errorf("%s: expected 314 to fire, got %+v", typ, f)
		}
	}
	if f := runRule(sqlWeakAdminPassword{}, res("azurerm_storage_account", "s", map[string]ir.Value{
		"administrator_login_password": ks("password123", 3),
	})); len(f) != 0 {
		t.Errorf("storage account must not match 314, got %+v", f)
	}
}

// TestAZURE314_EndToEndCombat: the combat-test shape — a legacy
// azurerm_sql_server with a weak admin password — fires, while the
// hardened shape (strong password + auditing) stays quiet for 314.
func TestAZURE314_EndToEndCombat(t *testing.T) {
	weak := `resource "azurerm_sql_server" "weak" {
  name = "sql1" resource_group_name = "rg" location = "westeurope" version = "12.0"
  administrator_login = "a" administrator_login_password = "Password123!"
}
`
	mod, _, err := (terraform.Adapter{}).ParseModule("t.tf", []byte(weak))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f := runRule(sqlWeakAdminPassword{}, mod.Resources[0]); len(f) != 1 {
		t.Fatalf("expected 314 on combat weak SQL server, got %+v", f)
	}
	hardened := `resource "azurerm_sql_server" "ok" {
  name = "sql1"
  resource_group_name = "rg"
  location = "westeurope"
  version = "12.0"
  administrator_login = "a"
  administrator_login_password = "Str0ng-4c2865-Db!"
  extended_auditing_policy {
    storage_endpoint = "https://st.blob.core.windows.net/"
    retention_in_days = 90
  }
}
`
	mod2, _, err := (terraform.Adapter{}).ParseModule("t.tf", []byte(hardened))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f := runRule(sqlWeakAdminPassword{}, mod2.Resources[0]); len(f) != 0 {
		t.Fatalf("hardened SQL server must stay quiet for 314, got %+v", f)
	}
	if f := runRuleAll(mssqlNoExtAuditPolicy{}, mod2.Resources[0]); len(f) != 0 {
		t.Fatalf("hardened SQL server must stay quiet for 101, got %+v", f)
	}
}

// TestAZURE101_LegacySQLServer: auditing coverage extends to the legacy
// azurerm_sql_server type (previously via AEGIS-AZURE-009, now via 101).
func TestAZURE101_LegacySQLServer(t *testing.T) {
	r := res("azurerm_sql_server", "s", map[string]ir.Value{})
	mustFinding(t, runRuleAll(mssqlNoExtAuditPolicy{}, r), "AEGIS-AZURE-101")
	r2 := res("azurerm_sql_server", "s", map[string]ir.Value{
		"extended_auditing_policy": blks(3, blk("storage_endpoint", ks("https://x", 4))),
	})
	if f := runRuleAll(mssqlNoExtAuditPolicy{}, r2); len(f) != 0 {
		t.Fatalf("legacy SQL server with auditing must stay quiet, got %+v", f)
	}
}

// TestAzureSQL_VerifyExistingCoverage: TLS (105), firewall (207/208) and
// TDE (018/044) already cover SQL servers/databases; these tests pin
// that coverage so the legacy gap fix cannot silently drop it.
func TestAzureSQL_VerifyExistingCoverage(t *testing.T) {
	tlsLow := res("azurerm_mssql_server", "s", map[string]ir.Value{
		"minimum_tls_version": ks("1.0", 3),
	})
	mustFinding(t, runRule(mssqlTLSBelow12{}, tlsLow), "AEGIS-AZURE-105")
	tlsOK := res("azurerm_mssql_server", "s", map[string]ir.Value{
		"minimum_tls_version": ks("1.2", 3),
	})
	if f := runRule(mssqlTLSBelow12{}, tlsOK); len(f) != 0 {
		t.Fatalf("TLS 1.2 must stay quiet, got %+v", f)
	}
	fwOpen := res("azurerm_sql_firewall_rule", "f", map[string]ir.Value{
		"start_ip_address": ks("0.0.0.0", 3),
		"end_ip_address":   ks("255.255.255.255", 3),
	})
	mustFinding(t, runRule(sqlFirewallOpenLegacy{}, fwOpen), "AEGIS-AZURE-208")
	fwAzureSvcs := res("azurerm_sql_firewall_rule", "f", map[string]ir.Value{
		"start_ip_address": ks("0.0.0.0", 3),
		"end_ip_address":   ks("0.0.0.0", 3),
	})
	if f := runRule(sqlFirewallOpenLegacy{}, fwAzureSvcs); len(f) != 0 {
		t.Fatalf("allow-Azure-services rule (0.0.0.0-0.0.0.0) must stay quiet, got %+v", f)
	}
	dbNoTDE := res("azurerm_mssql_database", "d", map[string]ir.Value{
		"transparent_data_encryption_enabled": kv(false, 3),
	})
	mustFinding(t, runRule(sqlDBNoTDE{}, dbNoTDE), "AEGIS-AZURE-018")
}
