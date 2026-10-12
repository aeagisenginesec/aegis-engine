package azure

import (
	"testing"

	"aegis/internal/ir"
)

// runRuleAll evaluates a cross-resource rule via CheckAll.
func runRuleAll(rule ir.CrossResourceRule, resources ...ir.Resource) []ir.Finding {
	return rule.CheckAll(resources)
}

func kref(ref string, line int) ir.Value {
	return ir.Value{Ref: ref, Known: false, Span: spanAt(line)}
}

func kf(f float64, line int) ir.Value {
	return ir.Value{Raw: f, Known: true, Span: spanAt(line)}
}

func block(line int, attrs map[string]ir.Value) ir.Value {
	return ir.Value{Raw: attrs, Known: true, Span: spanAt(line)}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-101
// ---------------------------------------------------------------------------

func TestAZURE101_NoAuditPolicyFires(t *testing.T) {
	srv := res("azurerm_mssql_server", "db", map[string]ir.Value{})
	mustFinding(t, runRuleAll(mssqlNoExtAuditPolicy{}, srv), "AEGIS-AZURE-101")
}

func TestAZURE101_PolicyRefQuiet(t *testing.T) {
	srv := res("azurerm_mssql_server", "db", map[string]ir.Value{})
	pol := res("azurerm_mssql_server_extended_auditing_policy", "audit", map[string]ir.Value{
		"server_id": kref("azurerm_mssql_server.db.id", 3),
	})
	if len(runRuleAll(mssqlNoExtAuditPolicy{}, srv, pol)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE101_InlineBlockQuiet(t *testing.T) {
	srv := res("azurerm_mssql_server", "db", map[string]ir.Value{
		"extended_auditing_policy": block(3, map[string]ir.Value{
			"storage_endpoint": ks("https://sa.blob.core.windows.net/", 4),
		}),
	})
	if len(runRuleAll(mssqlNoExtAuditPolicy{}, srv)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE101_OtherServerPolicyStillFires(t *testing.T) {
	srv := res("azurerm_mssql_server", "db", map[string]ir.Value{})
	pol := res("azurerm_mssql_server_extended_auditing_policy", "audit", map[string]ir.Value{
		"server_id": kref("azurerm_mssql_server.other.id", 3),
	})
	mustFinding(t, runRuleAll(mssqlNoExtAuditPolicy{}, srv, pol), "AEGIS-AZURE-101")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-102
// ---------------------------------------------------------------------------

func TestAZURE102_ShortRetentionFires(t *testing.T) {
	r := res("azurerm_mssql_server_extended_auditing_policy", "audit",
		map[string]ir.Value{"retention_in_days": kf(30, 3)})
	mustFinding(t, runRule(mssqlAuditRetentionLow{}, r), "AEGIS-AZURE-102")
}

func TestAZURE102_NinetyDaysQuiet(t *testing.T) {
	r := res("azurerm_mssql_server_extended_auditing_policy", "audit",
		map[string]ir.Value{"retention_in_days": kf(90, 3)})
	if len(runRule(mssqlAuditRetentionLow{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE102_ZeroIndefiniteQuiet(t *testing.T) {
	// Azure semantics: retention_in_days = 0 means retain indefinitely.
	r := res("azurerm_mssql_server_extended_auditing_policy", "audit",
		map[string]ir.Value{"retention_in_days": kf(0, 3)})
	if len(runRule(mssqlAuditRetentionLow{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE102_AbsentQuiet(t *testing.T) {
	r := res("azurerm_mssql_server_extended_auditing_policy", "audit", map[string]ir.Value{})
	if len(runRule(mssqlAuditRetentionLow{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-103
// ---------------------------------------------------------------------------

func TestAZURE103_DisabledAlertsFires(t *testing.T) {
	r := res("azurerm_mssql_server_security_alert_policy", "pol", map[string]ir.Value{
		"state":           ks("Enabled", 3),
		"disabled_alerts": strList(4, "Sql_Injection"),
	})
	mustFinding(t, runRule(mssqlThreatDetectPartial{}, r), "AEGIS-AZURE-103")
}

func TestAZURE103_StateDisabledFires(t *testing.T) {
	r := res("azurerm_mssql_server_security_alert_policy", "pol", map[string]ir.Value{
		"state": ks("Disabled", 3),
	})
	mustFinding(t, runRule(mssqlThreatDetectPartial{}, r), "AEGIS-AZURE-103")
}

func TestAZURE103_BothViolatedTwoFindings(t *testing.T) {
	r := res("azurerm_mssql_server_security_alert_policy", "pol", map[string]ir.Value{
		"state":           ks("Disabled", 3),
		"disabled_alerts": strList(4, "Sql_Injection"),
	})
	f := runRule(mssqlThreatDetectPartial{}, r)
	if len(f) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(f))
	}
}

func TestAZURE103_AllEnabledQuiet(t *testing.T) {
	r := res("azurerm_mssql_server_security_alert_policy", "pol", map[string]ir.Value{
		"state": ks("Enabled", 3),
	})
	if len(runRule(mssqlThreatDetectPartial{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-104
// ---------------------------------------------------------------------------

func TestAZURE104_EmailFalseFires(t *testing.T) {
	r := res("azurerm_mssql_server_security_alert_policy", "pol",
		map[string]ir.Value{"email_account_admins": kv(false, 3)})
	mustFinding(t, runRule(mssqlAlertEmailDisabled{}, r), "AEGIS-AZURE-104")
}

func TestAZURE104_AbsentFires(t *testing.T) {
	r := res("azurerm_mssql_server_security_alert_policy", "pol", map[string]ir.Value{})
	mustFinding(t, runRule(mssqlAlertEmailDisabled{}, r), "AEGIS-AZURE-104")
}

func TestAZURE104_EmailTrueQuiet(t *testing.T) {
	r := res("azurerm_mssql_server_security_alert_policy", "pol",
		map[string]ir.Value{"email_account_admins": kv(true, 3)})
	if len(runRule(mssqlAlertEmailDisabled{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-105
// ---------------------------------------------------------------------------

func TestAZURE105_OldTLSFires(t *testing.T) {
	r := res("azurerm_mssql_server", "db",
		map[string]ir.Value{"minimum_tls_version": ks("1.0", 3)})
	mustFinding(t, runRule(mssqlTLSBelow12{}, r), "AEGIS-AZURE-105")
}

func TestAZURE105_AbsentFires(t *testing.T) {
	r := res("azurerm_mssql_server", "db", map[string]ir.Value{})
	mustFinding(t, runRule(mssqlTLSBelow12{}, r), "AEGIS-AZURE-105")
}

func TestAZURE105_TLS12Quiet(t *testing.T) {
	r := res("azurerm_mssql_server", "db",
		map[string]ir.Value{"minimum_tls_version": ks("1.2", 3)})
	if len(runRule(mssqlTLSBelow12{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-106
// ---------------------------------------------------------------------------

func TestAZURE106_PublicTrueFires(t *testing.T) {
	r := res("azurerm_mssql_server", "db",
		map[string]ir.Value{"public_network_access_enabled": kv(true, 3)})
	mustFinding(t, runRule(mssqlPublicAccessDefault{}, r), "AEGIS-AZURE-106")
}

func TestAZURE106_AbsentFires(t *testing.T) {
	r := res("azurerm_mssql_server", "db", map[string]ir.Value{})
	mustFinding(t, runRule(mssqlPublicAccessDefault{}, r), "AEGIS-AZURE-106")
}

func TestAZURE106_PublicFalseQuiet(t *testing.T) {
	r := res("azurerm_mssql_server", "db",
		map[string]ir.Value{"public_network_access_enabled": kv(false, 3)})
	if len(runRule(mssqlPublicAccessDefault{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-107
// ---------------------------------------------------------------------------

func TestAZURE107_NoAdminFires(t *testing.T) {
	srv := res("azurerm_mssql_server", "db", map[string]ir.Value{})
	mustFinding(t, runRuleAll(mssqlNoADAdminResource{}, srv), "AEGIS-AZURE-107")
}

func TestAZURE107_AdminRefQuiet(t *testing.T) {
	srv := res("azurerm_mssql_server", "db", map[string]ir.Value{})
	adm := res("azurerm_mssql_server_azuread_administrator", "ad", map[string]ir.Value{
		"server_id": kref("azurerm_mssql_server.db.id", 3),
	})
	if len(runRuleAll(mssqlNoADAdminResource{}, srv, adm)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE107_InlineBlockQuiet(t *testing.T) {
	srv := res("azurerm_mssql_server", "db", map[string]ir.Value{
		"azuread_administrator": block(3, map[string]ir.Value{
			"login_username": ks("sqladmin", 4),
		}),
	})
	if len(runRuleAll(mssqlNoADAdminResource{}, srv)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-108
// ---------------------------------------------------------------------------

func TestAZURE108_NoPrivateEndpointFires(t *testing.T) {
	srv := res("azurerm_mssql_server", "db", map[string]ir.Value{})
	mustFinding(t, runRuleAll(mssqlNoPrivateEndpoint{}, srv), "AEGIS-AZURE-108")
}

func TestAZURE108_PrivateEndpointQuiet(t *testing.T) {
	srv := res("azurerm_mssql_server", "db", map[string]ir.Value{})
	pe := res("azurerm_private_endpoint", "pe", map[string]ir.Value{
		"private_service_connection": block(3, map[string]ir.Value{
			"private_connection_resource_id": kref("azurerm_mssql_server.db.id", 4),
			"subresource_names":              strList(5, "sqlServer"),
		}),
	})
	if len(runRuleAll(mssqlNoPrivateEndpoint{}, srv, pe)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE108_OtherServerPEStillFires(t *testing.T) {
	srv := res("azurerm_mssql_server", "db", map[string]ir.Value{})
	pe := res("azurerm_private_endpoint", "pe", map[string]ir.Value{
		"private_service_connection": block(3, map[string]ir.Value{
			"private_connection_resource_id": kref("azurerm_mssql_server.other.id", 4),
		}),
	})
	mustFinding(t, runRuleAll(mssqlNoPrivateEndpoint{}, srv, pe), "AEGIS-AZURE-108")
}
