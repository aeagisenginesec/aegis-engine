package azure

import (
	"strconv"
	"testing"

	"aegis/internal/ir"
)

// Pack registration: Azure21Rules must be wired into Rules() in ID order.
func TestAzure21RegisteredInIDOrder(t *testing.T) {
	rules := Rules()
	idx := map[string]int{}
	for i, r := range rules {
		idx[r.ID()] = i
	}
	// 298,312 removed as post-audit duplicates.
	want := []int{299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 313}
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

func adfRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_data_factory", "d", attrs)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-155..300: Data Factory family
// ---------------------------------------------------------------------------

func TestAZURE155_300(t *testing.T) {
	f := mustFinding(t, runRule(dataFactoryPublicNet{}, adfRes(nil)), "AEGIS-AZURE-155")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("155: wrong severity %s", f.Severity)
	}
	r := adfRes(map[string]ir.Value{"public_network_enabled": kv(false, 3)})
	if f := runRule(dataFactoryPublicNet{}, r); len(f) != 0 {
		t.Fatalf("298: disabled must not fire")
	}

	mustFinding(t, runRule(adfNoCMK{}, adfRes(nil)), "AEGIS-AZURE-299")
	r2 := adfRes(map[string]ir.Value{"customer_managed_key_id": ks("k", 3)})
	if f := runRule(adfNoCMK{}, r2); len(f) != 0 {
		t.Fatalf("299: CMK set must not fire")
	}

	mustFinding(t, runRule(adfNoManagedVNet{}, adfRes(nil)), "AEGIS-AZURE-300")
	r3 := adfRes(map[string]ir.Value{"managed_virtual_network_enabled": kv(true, 3)})
	if f := runRule(adfNoManagedVNet{}, r3); len(f) != 0 {
		t.Fatalf("300: enabled must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-301/302: Synapse family
// ---------------------------------------------------------------------------

func TestAZURE301_302(t *testing.T) {
	f := mustFinding(t, runRule(synapseDataExfil{}, res("azurerm_synapse_workspace", "s", nil)), "AEGIS-AZURE-301")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("301: wrong severity %s", f.Severity)
	}
	r := res("azurerm_synapse_workspace", "s", map[string]ir.Value{"data_exfiltration_protection_enabled": kv(true, 3)})
	if f := runRule(synapseDataExfil{}, r); len(f) != 0 {
		t.Fatalf("301: enabled must not fire")
	}

	mustFinding(t, runRule(synapseNoCMK{}, res("azurerm_synapse_workspace", "s", nil)), "AEGIS-AZURE-302")
	r2 := res("azurerm_synapse_workspace", "s", map[string]ir.Value{
		"customer_managed_key": blks(3, blk("key_vault_key_id", ks("k", 4))),
	})
	if f := runRule(synapseNoCMK{}, r2); len(f) != 0 {
		t.Fatalf("302: CMK present must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-303/304: Databricks family
// ---------------------------------------------------------------------------

func TestAZURE303_304(t *testing.T) {
	mustFinding(t, runRule(databricksInfraEnc{}, res("azurerm_databricks_workspace", "d", nil)), "AEGIS-AZURE-303")
	r := res("azurerm_databricks_workspace", "d", map[string]ir.Value{"infrastructure_encryption_enabled": kv(true, 3)})
	if f := runRule(databricksInfraEnc{}, r); len(f) != 0 {
		t.Fatalf("303: enabled must not fire")
	}

	mustFinding(t, runRule(databricksNoPublicIP{}, res("azurerm_databricks_workspace", "d", nil)), "AEGIS-AZURE-304")
	r2 := res("azurerm_databricks_workspace", "d", map[string]ir.Value{
		"custom_parameters": blks(3, blk("no_public_ip", kv(true, 4))),
	})
	if f := runRule(databricksNoPublicIP{}, r2); len(f) != 0 {
		t.Fatalf("304: no_public_ip must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-305..308: IoT Hub family
// ---------------------------------------------------------------------------

func TestAZURE305_308(t *testing.T) {
	mustFinding(t, runRule(iotHubNoIPFilter{}, res("azurerm_iothub", "i", nil)), "AEGIS-AZURE-305")
	r := res("azurerm_iothub", "i", map[string]ir.Value{
		"ip_filter_rule": blks(3, blk("ip_mask", ks("10.0.0.0/8", 4), "action", ks("Accept", 4))),
	})
	if f := runRule(iotHubNoIPFilter{}, r); len(f) != 0 {
		t.Fatalf("305: filter present must not fire")
	}
	r2 := res("azurerm_iothub", "i", map[string]ir.Value{"public_network_access_enabled": kv(false, 3)})
	if f := runRule(iotHubNoIPFilter{}, r2); len(f) != 0 {
		t.Fatalf("305: private must not fire")
	}

	mustFinding(t, runRule(iotHubSAPRegWrite{}, res("azurerm_iothub_shared_access_policy", "p", map[string]ir.Value{"registry_write": kv(true, 3)})), "AEGIS-AZURE-306")
	if f := runRule(iotHubSAPRegWrite{}, res("azurerm_iothub_shared_access_policy", "p", nil)); len(f) != 0 {
		t.Fatalf("306: absent (default false) must not fire")
	}

	mustFinding(t, runRule(iotHubMinTLS{}, res("azurerm_iothub", "i", map[string]ir.Value{"min_tls_version": ks("1.0", 3)})), "AEGIS-AZURE-307")
	r3 := res("azurerm_iothub", "i", map[string]ir.Value{"min_tls_version": ks("1.2", 3)})
	if f := runRule(iotHubMinTLS{}, r3); len(f) != 0 {
		t.Fatalf("307: 1.2 must not fire")
	}

	mustFinding(t, runRule(iotHubFallbackRoute{}, res("azurerm_iothub", "i", nil)), "AEGIS-AZURE-308")
	r4 := res("azurerm_iothub", "i", map[string]ir.Value{
		"fallback_route": blks(3, blk("enabled", kv(true, 4))),
	})
	if f := runRule(iotHubFallbackRoute{}, r4); len(f) != 0 {
		t.Fatalf("308: fallback route present must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-309..311: Cognitive Services family
// ---------------------------------------------------------------------------

func TestAZURE309_311(t *testing.T) {
	mustFinding(t, runRule(cognitiveNetACLs{}, res("azurerm_cognitive_account", "c", map[string]ir.Value{
		"network_acls": blks(3, blk("default_action", ks("Allow", 4))),
	})), "AEGIS-AZURE-309")
	r := res("azurerm_cognitive_account", "c", map[string]ir.Value{
		"network_acls": blks(3, blk("default_action", ks("Deny", 4))),
	})
	if f := runRule(cognitiveNetACLs{}, r); len(f) != 0 {
		t.Fatalf("309: Deny must not fire")
	}
	if f := runRule(cognitiveNetACLs{}, res("azurerm_cognitive_account", "c", nil)); len(f) != 0 {
		t.Fatalf("309: absent network_acls must not fire")
	}

	mustFinding(t, runRule(cognitiveNoCMK{}, res("azurerm_cognitive_account", "c", nil)), "AEGIS-AZURE-310")

	mustFinding(t, runRule(cognitiveLocalAuth{}, res("azurerm_cognitive_account", "c", nil)), "AEGIS-AZURE-311")
	r2 := res("azurerm_cognitive_account", "c", map[string]ir.Value{"local_auth_enabled": kv(false, 3)})
	if f := runRule(cognitiveLocalAuth{}, r2); len(f) != 0 {
		t.Fatalf("311: disabled local auth must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-020/313: Redis family
// ---------------------------------------------------------------------------

func TestAZURE020_313(t *testing.T) {
	mustFinding(t, runRule(redisWeakTLS{}, res("azurerm_redis_cache", "r", map[string]ir.Value{"minimum_tls_version": ks("1.0", 3)})), "AEGIS-AZURE-020")
	r := res("azurerm_redis_cache", "r", map[string]ir.Value{"minimum_tls_version": ks("1.2", 3)})
	if f := runRule(redisWeakTLS{}, r); len(f) != 0 {
		t.Fatalf("020: 1.2 must not fire")
	}

	f := mustFinding(t, runRule(redisPublicNet{}, res("azurerm_redis_cache", "r", nil)), "AEGIS-AZURE-313")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("313: wrong severity %s", f.Severity)
	}
	r2 := res("azurerm_redis_cache", "r", map[string]ir.Value{"public_network_access_enabled": kv(false, 3)})
	if f := runRule(redisPublicNet{}, r2); len(f) != 0 {
		t.Fatalf("313: disabled must not fire")
	}
}
