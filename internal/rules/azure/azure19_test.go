package azure

import (
	"strconv"
	"testing"

	"aegis/internal/ir"
)

// Pack registration: Azure19Rules must be wired into Rules() in ID order.
func TestAzure19RegisteredInIDOrder(t *testing.T) {
	rules := Rules()
	idx := map[string]int{}
	for i, r := range rules {
		idx[r.ID()] = i
	}
	for n := 262; n <= 281; n++ {
		id := "AEGIS-AZURE-" + strconv.Itoa(n)
		i, ok := idx[id]
		if !ok {
			t.Fatalf("rule %s not registered", id)
		}
		if n > 262 {
			prev := "AEGIS-AZURE-" + strconv.Itoa(n-1)
			if idx[prev] != i-1 {
				t.Fatalf("rules out of order: %s at %d, %s at %d", prev, idx[prev], id, i)
			}
		}
	}
}

func cosmosRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_cosmosdb_account", "c", attrs)
}

func ehnsRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_eventhub_namespace", "e", attrs)
}

func sbnsRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_servicebus_namespace", "s", attrs)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-262..265: Cosmos DB family
// ---------------------------------------------------------------------------

func TestAZURE262_265(t *testing.T) {
	mustFinding(t, runRule(cosmosNoContBackup{}, cosmosRes(nil)), "AEGIS-AZURE-262")
	r := cosmosRes(map[string]ir.Value{
		"backup": blks(3, blk("type", ks("Continuous", 4))),
	})
	if f := runRule(cosmosNoContBackup{}, r); len(f) != 0 {
		t.Fatalf("262: continuous backup must not fire")
	}

	f := mustFinding(t, runRule(cosmosPublicNet{}, cosmosRes(nil)), "AEGIS-AZURE-263")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("263: wrong severity %s", f.Severity)
	}
	r2 := cosmosRes(map[string]ir.Value{"public_network_access_enabled": kv(false, 3)})
	if f := runRule(cosmosPublicNet{}, r2); len(f) != 0 {
		t.Fatalf("263: disabled must not fire")
	}

	mustFinding(t, runRule(cosmosMinTLS{}, cosmosRes(map[string]ir.Value{"minimal_tls_version": ks("Tls10", 3)})), "AEGIS-AZURE-264")
	r3 := cosmosRes(map[string]ir.Value{"minimal_tls_version": ks("Tls12", 3)})
	if f := runRule(cosmosMinTLS{}, r3); len(f) != 0 {
		t.Fatalf("264: Tls12 must not fire")
	}

	mustFinding(t, runRule(cosmosLocalAuth{}, cosmosRes(nil)), "AEGIS-AZURE-265")
	r4 := cosmosRes(map[string]ir.Value{"local_authentication_disabled": kv(true, 3)})
	if f := runRule(cosmosLocalAuth{}, r4); len(f) != 0 {
		t.Fatalf("265: disabled local auth must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-266..269,281: Event Hub family
// ---------------------------------------------------------------------------

func TestAZURE266_269_281(t *testing.T) {
	mustFinding(t, runRule(eventHubMinTLS{}, ehnsRes(map[string]ir.Value{"minimum_tls_version": ks("1.0", 3)})), "AEGIS-AZURE-266")
	r := ehnsRes(map[string]ir.Value{"minimum_tls_version": ks("1.2", 3)})
	if f := runRule(eventHubMinTLS{}, r); len(f) != 0 {
		t.Fatalf("266: 1.2 must not fire")
	}

	f := mustFinding(t, runRule(eventHubPublicNet{}, ehnsRes(nil)), "AEGIS-AZURE-267")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("267: wrong severity %s", f.Severity)
	}

	mustFinding(t, runRule(eventHubLocalAuth{}, ehnsRes(nil)), "AEGIS-AZURE-268")
	r2 := ehnsRes(map[string]ir.Value{"local_auth_enabled": kv(false, 3)})
	if f := runRule(eventHubLocalAuth{}, r2); len(f) != 0 {
		t.Fatalf("268: disabled local auth must not fire")
	}

	mustFinding(t, runRule(eventHubManageRule{}, res("azurerm_eventhub_authorization_rule", "a", map[string]ir.Value{"manage": kv(true, 3)})), "AEGIS-AZURE-269")
	if f := runRule(eventHubManageRule{}, res("azurerm_eventhub_authorization_rule", "a", nil)); len(f) != 0 {
		t.Fatalf("269: absent (default false) must not fire")
	}

	mustFinding(t, runRule(eventHubNoVNetRule{}, ehnsRes(nil)), "AEGIS-AZURE-281")
	r3 := ehnsRes(map[string]ir.Value{
		"network_rulesets": blks(3, blk("default_action", ks("Deny", 4))),
	})
	if f := runRule(eventHubNoVNetRule{}, r3); len(f) != 0 {
		t.Fatalf("281: Deny must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-270..273,278: Service Bus family
// ---------------------------------------------------------------------------

func TestAZURE270_273_278(t *testing.T) {
	mustFinding(t, runRule(serviceBusMinTLS{}, sbnsRes(map[string]ir.Value{"minimum_tls_version": ks("1.0", 3)})), "AEGIS-AZURE-270")
	r := sbnsRes(map[string]ir.Value{"minimum_tls_version": ks("1.2", 3)})
	if f := runRule(serviceBusMinTLS{}, r); len(f) != 0 {
		t.Fatalf("270: 1.2 must not fire")
	}

	f := mustFinding(t, runRule(serviceBusPublicNet{}, sbnsRes(nil)), "AEGIS-AZURE-271")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("271: wrong severity %s", f.Severity)
	}

	mustFinding(t, runRule(serviceBusLocalAuth{}, sbnsRes(nil)), "AEGIS-AZURE-272")
	r2 := sbnsRes(map[string]ir.Value{"local_auth_enabled": kv(false, 3)})
	if f := runRule(serviceBusLocalAuth{}, r2); len(f) != 0 {
		t.Fatalf("272: disabled must not fire")
	}

	mustFinding(t, runRule(serviceBusNoVNetRule{}, sbnsRes(nil)), "AEGIS-AZURE-273")
	r2b := sbnsRes(map[string]ir.Value{
		"network_rule_set": blks(3, blk("default_action", ks("Deny", 4))),
	})
	if f := runRule(serviceBusNoVNetRule{}, r2b); len(f) != 0 {
		t.Fatalf("273: Deny must not fire")
	}

	mustFinding(t, runRule(serviceBusDuplicateDetect{}, res("azurerm_servicebus_queue", "q", nil)), "AEGIS-AZURE-278")
	r3 := res("azurerm_servicebus_queue", "q", map[string]ir.Value{"requires_duplicate_detection": kv(true, 3)})
	if f := runRule(serviceBusDuplicateDetect{}, r3); len(f) != 0 {
		t.Fatalf("278: enabled must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-274/275/279: APIM family
// ---------------------------------------------------------------------------

func TestAZURE274_275_279(t *testing.T) {
	mustFinding(t, runRule(apimAPISubRequired{}, res("azurerm_api_management_api", "a", map[string]ir.Value{"subscription_required": kv(false, 3)})), "AEGIS-AZURE-274")
	if f := runRule(apimAPISubRequired{}, res("azurerm_api_management_api", "a", nil)); len(f) != 0 {
		t.Fatalf("274: absent (default true) must not fire")
	}

	f := mustFinding(t, runRule(apimAPIHTTPSOnly{}, res("azurerm_api_management_api", "a", map[string]ir.Value{
		"protocols": strList(3, "http", "https"),
	})), "AEGIS-AZURE-275")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("275: wrong severity %s", f.Severity)
	}
	r := res("azurerm_api_management_api", "a", map[string]ir.Value{
		"protocols": strList(3, "https"),
	})
	if f := runRule(apimAPIHTTPSOnly{}, r); len(f) != 0 {
		t.Fatalf("275: https-only must not fire")
	}

	mustFinding(t, runRule(apimAPINoRateLimit{}, res("azurerm_api_management_api_version_set", "v", nil)), "AEGIS-AZURE-279")
	r2 := res("azurerm_api_management_api_version_set", "v", map[string]ir.Value{"versioning_scheme": ks("Segment", 3)})
	if f := runRule(apimAPINoRateLimit{}, r2); len(f) != 0 {
		t.Fatalf("279: scheme set must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-276/277/280: misc
// ---------------------------------------------------------------------------

func TestAZURE276_277_280(t *testing.T) {
	mustFinding(t, runRule(cosmosKeyMetadataWrite{}, cosmosRes(nil)), "AEGIS-AZURE-276")
	r := cosmosRes(map[string]ir.Value{"access_key_metadata_writes_enabled": kv(false, 3)})
	if f := runRule(cosmosKeyMetadataWrite{}, r); len(f) != 0 {
		t.Fatalf("276: disabled must not fire")
	}

	mustFinding(t, runRule(eventHubCaptureOff{}, res("azurerm_eventhub", "e", nil)), "AEGIS-AZURE-277")
	r2 := res("azurerm_eventhub", "e", map[string]ir.Value{
		"capture_description": blks(3, blk("enabled", kv(true, 4))),
	})
	if f := runRule(eventHubCaptureOff{}, r2); len(f) != 0 {
		t.Fatalf("277: capture enabled must not fire")
	}

	mustFinding(t, runRule(cosmosAnalyticalStore{}, cosmosRes(map[string]ir.Value{"analytical_storage_enabled": kv(true, 3)})), "AEGIS-AZURE-280")
	if f := runRule(cosmosAnalyticalStore{}, cosmosRes(nil)); len(f) != 0 {
		t.Fatalf("280: absent (default false) must not fire")
	}
}
