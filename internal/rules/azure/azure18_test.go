package azure

import (
	"strconv"
	"testing"

	"aegis/internal/ir"
)

// Pack registration: Azure18Rules must be wired into Rules() in ID order.
func TestAzure18RegisteredInIDOrder(t *testing.T) {
	rules := Rules()
	idx := map[string]int{}
	for i, r := range rules {
		idx[r.ID()] = i
	}
	for n := 246; n <= 261; n++ {
		id := "AEGIS-AZURE-" + strconv.Itoa(n)
		i, ok := idx[id]
		if !ok {
			t.Fatalf("rule %s not registered", id)
		}
		if n > 246 {
			prev := "AEGIS-AZURE-" + strconv.Itoa(n-1)
			if idx[prev] != i-1 {
				t.Fatalf("rules out of order: %s at %d, %s at %d", prev, idx[prev], id, i)
			}
		}
	}
}

func acrRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_container_registry", "acr", attrs)
}

func lawRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_log_analytics_workspace", "law", attrs)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-246: Defender plan tier
// ---------------------------------------------------------------------------

func TestAZURE246(t *testing.T) {
	id := "AEGIS-AZURE-246"
	f := mustFinding(t, runRule(defenderPlanNotStandard{}, res("azurerm_security_center_subscription_pricing", "p", map[string]ir.Value{"tier": ks("Free", 3)})), id)
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	r := res("azurerm_security_center_subscription_pricing", "p", map[string]ir.Value{"tier": ks("Standard", 3)})
	if f := runRule(defenderPlanNotStandard{}, r); len(f) != 0 {
		t.Fatalf("Standard must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-247: Security Center contact
// ---------------------------------------------------------------------------

func TestAZURE247(t *testing.T) {
	id := "AEGIS-AZURE-247"
	mustFinding(t, runRule(secContactNoNotify{}, res("azurerm_security_center_contact", "c", nil)), id)
	r := res("azurerm_security_center_contact", "c", map[string]ir.Value{"alert_notifications": kv(true, 3)})
	if f := runRule(secContactNoNotify{}, r); len(f) != 0 {
		t.Fatalf("enabled must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-248..250: Log Analytics family
// ---------------------------------------------------------------------------

func TestAZURE248_250(t *testing.T) {
	mustFinding(t, runRule(logAnalyticsLowRetain{}, lawRes(map[string]ir.Value{"retention_in_days": kn(30, 3)})), "AEGIS-AZURE-248")
	r := lawRes(map[string]ir.Value{"retention_in_days": kn(365, 3)})
	if f := runRule(logAnalyticsLowRetain{}, r); len(f) != 0 {
		t.Fatalf("248: 365 days must not fire")
	}

	mustFinding(t, runRule(logAnalyticsPubIngest{}, lawRes(nil)), "AEGIS-AZURE-249")
	r2 := lawRes(map[string]ir.Value{"internet_ingestion_enabled": kv(false, 3)})
	if f := runRule(logAnalyticsPubIngest{}, r2); len(f) != 0 {
		t.Fatalf("249: disabled must not fire")
	}

	mustFinding(t, runRule(logAnalyticsPubQuery{}, lawRes(nil)), "AEGIS-AZURE-250")
	r3 := lawRes(map[string]ir.Value{"internet_query_enabled": kv(false, 3)})
	if f := runRule(logAnalyticsPubQuery{}, r3); len(f) != 0 {
		t.Fatalf("250: disabled must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-251..257,261: ACR family
// ---------------------------------------------------------------------------

func TestAZURE251_257_261(t *testing.T) {
	mustFinding(t, runRule(acrNoTrustPolicy{}, acrRes(nil)), "AEGIS-AZURE-251")
	r := acrRes(map[string]ir.Value{"trust_policy_enabled": kv(true, 3)})
	if f := runRule(acrNoTrustPolicy{}, r); len(f) != 0 {
		t.Fatalf("251: enabled must not fire")
	}

	f := mustFinding(t, runRule(acrAnonPull{}, acrRes(map[string]ir.Value{"anonymous_pull_enabled": kv(true, 3)})), "AEGIS-AZURE-252")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("252: wrong severity %s", f.Severity)
	}
	if f := runRule(acrAnonPull{}, acrRes(nil)); len(f) != 0 {
		t.Fatalf("252: absent (default false) must not fire")
	}

	mustFinding(t, runRule(acrNetRulesOpen{}, acrRes(map[string]ir.Value{
		"network_rule_set": blks(3, blk("default_action", ks("Allow", 4))),
	})), "AEGIS-AZURE-253")
	r2 := acrRes(map[string]ir.Value{
		"network_rule_set": blks(3, blk("default_action", ks("Deny", 4))),
	})
	if f := runRule(acrNetRulesOpen{}, r2); len(f) != 0 {
		t.Fatalf("253: Deny must not fire")
	}

	mustFinding(t, runRule(acrExportPolicyOn{}, acrRes(map[string]ir.Value{"export_policy_enabled": kv(true, 3)})), "AEGIS-AZURE-254")
	if f := runRule(acrExportPolicyOn{}, acrRes(nil)); len(f) != 0 {
		t.Fatalf("254: absent must not fire")
	}

	mustFinding(t, runRule(acrPublicNet{}, acrRes(nil)), "AEGIS-AZURE-255")
	r3 := acrRes(map[string]ir.Value{"public_network_access_enabled": kv(false, 3)})
	if f := runRule(acrPublicNet{}, r3); len(f) != 0 {
		t.Fatalf("255: disabled must not fire")
	}

	mustFinding(t, runRule(acrTaskRuns{}, res("azurerm_container_registry_task", "t", map[string]ir.Value{
		"encoded_values": ir.Value{Raw: map[string]ir.Value{"db_password": ks("s3cret", 4)}, Known: true, Span: spanAt(3)},
	})), "AEGIS-AZURE-256")
	if f := runRule(acrTaskRuns{}, res("azurerm_container_registry_task", "t", nil)); len(f) != 0 {
		t.Fatalf("256: no encoded_values must not fire")
	}

	mustFinding(t, runRule(acrNoCMK{}, acrRes(nil)), "AEGIS-AZURE-257")
	r4 := acrRes(map[string]ir.Value{
		"encryption": blks(3, blk("key_vault_key_id", ks("k", 4))),
	})
	if f := runRule(acrNoCMK{}, r4); len(f) != 0 {
		t.Fatalf("257: encryption present must not fire")
	}

	mustFinding(t, runRule(acrRetentionOff{}, acrRes(nil)), "AEGIS-AZURE-261")
	r5 := acrRes(map[string]ir.Value{
		"retention_policy": blks(3, blk("enabled", kv(true, 4), "days", kn(7, 4))),
	})
	if f := runRule(acrRetentionOff{}, r5); len(f) != 0 {
		t.Fatalf("261: enabled retention must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-258: App Insights retention
// ---------------------------------------------------------------------------

func TestAZURE258(t *testing.T) {
	id := "AEGIS-AZURE-258"
	mustFinding(t, runRule(appInsightsLowRetain{}, res("azurerm_application_insights", "a", map[string]ir.Value{"retention_in_days": kn(30, 3)})), id)
	if f := runRule(appInsightsLowRetain{}, res("azurerm_application_insights", "a", nil)); len(f) != 0 {
		t.Fatalf("absent (default 90) must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-259: Log Analytics CMK
// ---------------------------------------------------------------------------

func TestAZURE259(t *testing.T) {
	id := "AEGIS-AZURE-259"
	mustFinding(t, runRule(logAnalyticsNoCMK{}, lawRes(nil)), id)
	r := lawRes(map[string]ir.Value{"customer_managed_key_id": ks("k", 3)})
	if f := runRule(logAnalyticsNoCMK{}, r); len(f) != 0 {
		t.Fatalf("CMK set must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-260: Defender for ARM
// ---------------------------------------------------------------------------

func TestAZURE260(t *testing.T) {
	id := "AEGIS-AZURE-260"
	r := res("azurerm_security_center_subscription_pricing", "p", map[string]ir.Value{
		"resource_type": ks("Arm", 3),
		"tier":          ks("Free", 4),
	})
	mustFinding(t, runRule(defenderARMPlanOff{}, r), id)
	r2 := res("azurerm_security_center_subscription_pricing", "p", map[string]ir.Value{
		"resource_type": ks("Arm", 3),
		"tier":          ks("Standard", 4),
	})
	if f := runRule(defenderARMPlanOff{}, r2); len(f) != 0 {
		t.Fatalf("Standard Arm must not fire, got %d", len(f))
	}
	r3 := res("azurerm_security_center_subscription_pricing", "p", map[string]ir.Value{
		"resource_type": ks("VirtualMachines", 3),
		"tier":          ks("Free", 4),
	})
	if f := runRule(defenderARMPlanOff{}, r3); len(f) != 0 {
		t.Fatalf("non-Arm must not fire 260, got %d", len(f))
	}
}
