package arm

// Twin tests for the VNet DDoS merge fix. Before the fix, the ARM
// properties enableDdosProtection (bool, renamed by the type map)
// and ddosProtectionPlan (object, snake_cased) collided on the
// single IR attribute ddos_protection_plan, and mapResource's
// first-writer-wins guard let Go map iteration order pick the
// winner: when the plan object won, AEGIS-AZURE-057 saw a block
// without enable and fired on compliant VNets (the intermittent
// compliant-gate failure); when the bare bool won, the rule could
// not decide at all. The merge is deterministic: one block value
// carrying exactly the facts the template states.

import (
	"testing"

	"aegis/internal/ir"
)

func vnetTemplate(props string) string {
	return `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Network/virtualNetworks",
      "apiVersion": "2023-05-01",
      "name": "ddosvnet",
      "location": "westeurope",
      "properties": { ` + props + ` }
    }
  ]
}`
}

func parseVNet(t *testing.T, tmpl string) ir.Resource {
	t.Helper()
	res, _, err := New().Parse("azuredeploy.json", []byte(tmpl))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, r := range res {
		if r.Type == "azurerm_virtual_network" {
			return r
		}
	}
	t.Fatalf("no azurerm_virtual_network in parse output (%d resources)", len(res))
	return ir.Resource{}
}

func ddosBlock(t *testing.T, r ir.Resource) map[string]ir.Value {
	t.Helper()
	v, ok := r.Attributes["ddos_protection_plan"]
	if !ok {
		t.Fatalf("ddos_protection_plan attribute missing")
	}
	m, ok := v.AsMap()
	if !ok {
		t.Fatalf("ddos_protection_plan is %T, want a block map", v.Raw)
	}
	return m
}

func TestVNetDdosMerge_BothProperties(t *testing.T) {
	tmpl := vnetTemplate(`
        "enableDdosProtection": true,
        "ddosProtectionPlan": { "id": "[resourceId('Microsoft.Network/ddosProtectionPlans', 'plan1')]" }`)
	// The pre-fix failure was order-dependent: parse repeatedly and
	// require the identical merged block every single time.
	for i := 0; i < 50; i++ {
		m := ddosBlock(t, parseVNet(t, tmpl))
		en, ok := m["enable"]
		if !ok {
			t.Fatalf("iteration %d: merged block has no enable (plan object won the race?)", i)
		}
		if b, kok := en.AsBool(); !kok || !b {
			t.Fatalf("iteration %d: enable = %v, want known true", i, en.Raw)
		}
		if _, ok := m["id"]; !ok {
			t.Fatalf("iteration %d: merged block lost the plan id", i)
		}
	}
}

func TestVNetDdosMerge_EnableFalseKept(t *testing.T) {
	tmpl := vnetTemplate(`
        "enableDdosProtection": false,
        "ddosProtectionPlan": { "id": "plan-id" }`)
	m := ddosBlock(t, parseVNet(t, tmpl))
	en, ok := m["enable"]
	if !ok {
		t.Fatalf("merged block has no enable")
	}
	if b, kok := en.AsBool(); !kok || b {
		t.Fatalf("enable = %v, want known false (rule must be able to fire)", en.Raw)
	}
}

func TestVNetDdosMerge_BoolOnly(t *testing.T) {
	tmpl := vnetTemplate(`"enableDdosProtection": true`)
	m := ddosBlock(t, parseVNet(t, tmpl))
	en, ok := m["enable"]
	if !ok {
		t.Fatalf("merged block has no enable")
	}
	if b, kok := en.AsBool(); !kok || !b {
		t.Fatalf("enable = %v, want known true", en.Raw)
	}
}

func TestVNetDdosMerge_PlanOnlyNoInventedEnable(t *testing.T) {
	tmpl := vnetTemplate(`"ddosProtectionPlan": { "id": "plan-id" }`)
	m := ddosBlock(t, parseVNet(t, tmpl))
	if _, ok := m["id"]; !ok {
		t.Fatalf("merged block lost the plan id")
	}
	if _, ok := m["enable"]; ok {
		t.Fatalf("enable was invented for a template that never states it")
	}
}

func TestVNetDdosMerge_NeitherProperty(t *testing.T) {
	tmpl := vnetTemplate(`"addressSpace": { "addressPrefixes": ["10.0.0.0/16"] }`)
	r := parseVNet(t, tmpl)
	if _, ok := r.Attributes["ddos_protection_plan"]; ok {
		t.Fatalf("ddos_protection_plan synthesized from nothing")
	}
}
