package azure

import (
	"strconv"
	"testing"

	"aegis/internal/ir"
)

// Pack registration: Azure13Rules must be wired into Rules() in ID order.
func TestAzure13RegisteredInIDOrder(t *testing.T) {
	rules := Rules()
	idx := map[string]int{}
	for i, r := range rules {
		idx[r.ID()] = i
	}
	for n := 150; n <= 169; n++ {
		id := "AEGIS-AZURE-" + strconv.Itoa(n)
		i, ok := idx[id]
		if !ok {
			t.Fatalf("rule %s not registered", id)
		}
		if n > 150 {
			prev := "AEGIS-AZURE-" + strconv.Itoa(n-1)
			if idx[prev] != i-1 {
				t.Fatalf("rules out of order: %s at %d, %s at %d", prev, idx[prev], id, i)
			}
		}
	}
}

func funcAppRes(typ string, attrs map[string]ir.Value) ir.Resource {
	return res(typ, "app", attrs)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-150: Function App without HTTPS-only
// ---------------------------------------------------------------------------

func TestAZURE150(t *testing.T) {
	id := "AEGIS-AZURE-150"
	for _, typ := range []string{"azurerm_function_app", "azurerm_linux_function_app"} {
		mustFinding(t, runRule(funcAppNoHTTPS{}, funcAppRes(typ, nil)), id)
		mustFinding(t, runRule(funcAppNoHTTPS{}, funcAppRes(typ, map[string]ir.Value{"https_only": kv(false, 3)})), id)
		if f := runRule(funcAppNoHTTPS{}, funcAppRes(typ, map[string]ir.Value{"https_only": kv(true, 3)})); len(f) != 0 {
			t.Fatalf("%s: enabled must not fire", typ)
		}
		if f := runRule(funcAppNoHTTPS{}, funcAppRes(typ, map[string]ir.Value{"https_only": ku(3)})); len(f) != 0 {
			t.Fatalf("%s: unknown must not fire", typ)
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-151: Function App without IP restrictions
// ---------------------------------------------------------------------------

func TestAZURE151(t *testing.T) {
	id := "AEGIS-AZURE-151"
	mustFinding(t, runRule(funcAppNoIPRestrict{}, funcAppRes("azurerm_function_app", nil)), id)
	r := funcAppRes("azurerm_function_app", map[string]ir.Value{
		"site_config": blks(3, blk("ip_restriction", blks(4, blk("ip_address", ks("10.0.0.0/8", 5))))),
	})
	if f := runRule(funcAppNoIPRestrict{}, r); len(f) != 0 {
		t.Fatalf("restricted app must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-152: Function App without managed identity
// ---------------------------------------------------------------------------

func TestAZURE152(t *testing.T) {
	id := "AEGIS-AZURE-152"
	mustFinding(t, runRule(funcAppNoIdentity{}, funcAppRes("azurerm_linux_function_app", nil)), id)
	r := funcAppRes("azurerm_linux_function_app", map[string]ir.Value{
		"identity": blks(3, blk("type", ks("SystemAssigned", 4))),
	})
	if f := runRule(funcAppNoIdentity{}, r); len(f) != 0 {
		t.Fatalf("identity app must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-153: API Management without virtual network
// ---------------------------------------------------------------------------

func TestAZURE153(t *testing.T) {
	id := "AEGIS-AZURE-153"
	mustFinding(t, runRule(apimNoVNet{}, res("azurerm_api_management", "a", nil)), id)
	r := res("azurerm_api_management", "a", map[string]ir.Value{"virtual_network_type": ks("None", 3)})
	mustFinding(t, runRule(apimNoVNet{}, r), id)
	r2 := res("azurerm_api_management", "a", map[string]ir.Value{"virtual_network_type": ks("Internal", 3)})
	if f := runRule(apimNoVNet{}, r2); len(f) != 0 {
		t.Fatalf("internal vnet must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-154..159: public-network-access family
// ---------------------------------------------------------------------------

func publicNetCases() []struct {
	rule ir.Rule
	id   string
	typ  string
	attr string
	sev  ir.Severity
} {
	return []struct {
		rule ir.Rule
		id   string
		typ  string
		attr string
		sev  ir.Severity
	}{
		{apimPublicNet{}, "AEGIS-AZURE-154", "azurerm_api_management", "public_network_access_enabled", ir.SeverityMedium},
		{dataFactoryPublicNet{}, "AEGIS-AZURE-155", "azurerm_data_factory", "public_network_enabled", ir.SeverityMedium},
		{databricksPublicNet{}, "AEGIS-AZURE-159", "azurerm_databricks_workspace", "public_network_access_enabled", ir.SeverityMedium},
		{eventGridPublicNet{}, "AEGIS-AZURE-160", "azurerm_eventgrid_topic", "public_network_access_enabled", ir.SeverityMedium},
		{mlWorkspacePublicNet{}, "AEGIS-AZURE-162", "azurerm_machine_learning_workspace", "public_network_access_enabled", ir.SeverityHigh},
		{appConfigPublicNet{}, "AEGIS-AZURE-164", "azurerm_app_configuration", "public_network_access_enabled", ir.SeverityMedium},
		{automationPublicNet{}, "AEGIS-AZURE-165", "azurerm_automation_account", "public_network_access_enabled", ir.SeverityMedium},
		{searchPublicNet{}, "AEGIS-AZURE-166", "azurerm_search_service", "public_network_access_enabled", ir.SeverityMedium},
		{cognitivePublicNet{}, "AEGIS-AZURE-167", "azurerm_cognitive_account", "public_network_access_enabled", ir.SeverityMedium},
		{iotHubPublicNet{}, "AEGIS-AZURE-168", "azurerm_iothub", "public_network_access_enabled", ir.SeverityHigh},
		{postgresFlexPublicNet{}, "AEGIS-AZURE-169", "azurerm_postgresql_flexible_server", "public_network_access_enabled", ir.SeverityHigh},
	}
}

func TestAZURE154_159_PublicNetFamily(t *testing.T) {
	for _, c := range publicNetCases() {
		f := mustFinding(t, runRule(c.rule, res(c.typ, "x", nil)), c.id)
		if f.Severity != c.sev {
			t.Fatalf("%s: wrong severity %s", c.id, f.Severity)
		}
		mustFinding(t, runRule(c.rule, res(c.typ, "x", map[string]ir.Value{c.attr: kv(true, 3)})), c.id)
		if fs := runRule(c.rule, res(c.typ, "x", map[string]ir.Value{c.attr: kv(false, 3)})); len(fs) != 0 {
			t.Fatalf("%s: disabled must not fire", c.id)
		}
		if fs := runRule(c.rule, res(c.typ, "x", map[string]ir.Value{c.attr: ku(3)})); len(fs) != 0 {
			t.Fatalf("%s: unknown must not fire", c.id)
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-156/157: Synapse workspace
// ---------------------------------------------------------------------------

func TestAZURE156_157(t *testing.T) {
	mustFinding(t, runRule(synapseNoManagedVNet{}, res("azurerm_synapse_workspace", "s", nil)), "AEGIS-AZURE-156")
	mustFinding(t, runRule(synapseNoExfilProtect{}, res("azurerm_synapse_workspace", "s", nil)), "AEGIS-AZURE-157")
	r := res("azurerm_synapse_workspace", "s", map[string]ir.Value{
		"managed_virtual_network_enabled":      kv(true, 3),
		"data_exfiltration_protection_enabled": kv(true, 4),
	})
	if f := runRule(synapseNoManagedVNet{}, r); len(f) != 0 {
		t.Fatalf("156: hardened must not fire")
	}
	if f := runRule(synapseNoExfilProtect{}, r); len(f) != 0 {
		t.Fatalf("157: hardened must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-158: Databricks workspace without customer-managed key
// ---------------------------------------------------------------------------

func TestAZURE158(t *testing.T) {
	id := "AEGIS-AZURE-158"
	mustFinding(t, runRule(databricksNoCMK{}, res("azurerm_databricks_workspace", "d", nil)), id)
	r := res("azurerm_databricks_workspace", "d", map[string]ir.Value{
		"customer_managed_key": blks(3, blk("key_vault_key_id", ks("k", 4))),
	})
	if f := runRule(databricksNoCMK{}, r); len(f) != 0 {
		t.Fatalf("cmk workspace must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-161: Event Grid topic with local authentication enabled
// ---------------------------------------------------------------------------

func TestAZURE161(t *testing.T) {
	id := "AEGIS-AZURE-161"
	mustFinding(t, runRule(eventGridLocalAuth{}, res("azurerm_eventgrid_topic", "e", nil)), id)
	mustFinding(t, runRule(eventGridLocalAuth{}, res("azurerm_eventgrid_domain", "e", nil)), id)
	r := res("azurerm_eventgrid_topic", "e", map[string]ir.Value{"local_auth_enabled": kv(false, 3)})
	if f := runRule(eventGridLocalAuth{}, r); len(f) != 0 {
		t.Fatalf("disabled local auth must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-163: App Configuration without purge protection
// ---------------------------------------------------------------------------

func TestAZURE163(t *testing.T) {
	id := "AEGIS-AZURE-163"
	mustFinding(t, runRule(appConfigNoPurge{}, res("azurerm_app_configuration", "c", nil)), id)
	r := res("azurerm_app_configuration", "c", map[string]ir.Value{"purge_protection_enabled": kv(true, 3)})
	if f := runRule(appConfigNoPurge{}, r); len(f) != 0 {
		t.Fatalf("protected config must not fire, got %d", len(f))
	}
}
