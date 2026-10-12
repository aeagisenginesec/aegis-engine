package azure

import (
	"strconv"
	"testing"

	"aegis/internal/ir"
)

// Pack registration: Azure17Rules must be wired into Rules() in ID order.
func TestAzure17RegisteredInIDOrder(t *testing.T) {
	rules := Rules()
	idx := map[string]int{}
	for i, r := range rules {
		idx[r.ID()] = i
	}
	// 234,243 removed as post-audit duplicates.
	want := []int{226, 227, 228, 229, 230, 231, 232, 233, 235, 236, 237, 238, 239, 240, 241, 242, 244, 245}
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

func aksRes17(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_kubernetes_cluster", "aks", attrs)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-226..228,231,234,245: AKS boolean family
// ---------------------------------------------------------------------------

func TestAZURE226_228_231_234_245(t *testing.T) {
	cases := []struct {
		rule ir.Rule
		id   string
		attr string
		sev  ir.Severity
	}{
		{aksNoOIDCIssuerStrict{}, "AEGIS-AZURE-136", "oidc_issuer_enabled", ir.SeverityLow},
		{aksLocalAccounts{}, "AEGIS-AZURE-245", "local_account_disabled", ir.SeverityMedium},
	}
	for _, c := range cases {
		f := mustFinding(t, runRule(c.rule, aksRes17(nil)), c.id)
		if f.Severity != c.sev {
			t.Fatalf("%s: wrong severity %s", c.id, f.Severity)
		}
		r := aksRes17(map[string]ir.Value{c.attr: kv(true, 3)})
		if fs := runRule(c.rule, r); len(fs) != 0 {
			t.Fatalf("%s: enabled must not fire", c.id)
		}
		if fs := runRule(c.rule, aksRes17(map[string]ir.Value{c.attr: ku(3)})); len(fs) != 0 {
			t.Fatalf("%s: unknown must not fire", c.id)
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-226: HTTP application routing
// ---------------------------------------------------------------------------

func TestAZURE226(t *testing.T) {
	id := "AEGIS-AZURE-226"
	f := mustFinding(t, runRule(aksHTTPRoutingOn{}, aksRes17(map[string]ir.Value{"http_application_routing_enabled": kv(true, 3)})), id)
	if f.Severity != ir.SeverityMedium {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	if f := runRule(aksHTTPRoutingOn{}, aksRes17(nil)); len(f) != 0 {
		t.Fatalf("absent (default false) must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-227: node pool auto-scaling
// ---------------------------------------------------------------------------

func TestAZURE227(t *testing.T) {
	id := "AEGIS-AZURE-227"
	mustFinding(t, runRule(aksNoAutoScaling{}, aksRes17(map[string]ir.Value{
		"default_node_pool": blks(3, blk()),
	})), id)
	r := aksRes17(map[string]ir.Value{
		"default_node_pool": blks(3, blk("enable_auto_scaling", kv(true, 4))),
	})
	if f := runRule(aksNoAutoScaling{}, r); len(f) != 0 {
		t.Fatalf("autoscaling on must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-231: run command
// ---------------------------------------------------------------------------

func TestAZURE231(t *testing.T) {
	id := "AEGIS-AZURE-231"
	f := mustFinding(t, runRule(aksRunCommandOn{}, aksRes17(nil)), id)
	if f.Severity != ir.SeverityMedium {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	r := aksRes17(map[string]ir.Value{"run_command_enabled": kv(false, 3)})
	if f := runRule(aksRunCommandOn{}, r); len(f) != 0 {
		t.Fatalf("disabled must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-232: LB SKU
// ---------------------------------------------------------------------------

func TestAZURE232(t *testing.T) {
	id := "AEGIS-AZURE-232"
	mustFinding(t, runRule(aksLBNotStandard{}, aksRes17(map[string]ir.Value{
		"network_profile": blks(3, blk("load_balancer_sku", ks("basic", 4))),
	})), id)
	r := aksRes17(map[string]ir.Value{
		"network_profile": blks(3, blk("load_balancer_sku", ks("standard", 4))),
	})
	if f := runRule(aksLBNotStandard{}, r); len(f) != 0 {
		t.Fatalf("standard must not fire, got %d", len(f))
	}
	if f := runRule(aksLBNotStandard{}, aksRes17(nil)); len(f) != 0 {
		t.Fatalf("absent (default standard) must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-228: node OS auto-upgrade
// ---------------------------------------------------------------------------

func TestAZURE228(t *testing.T) {
	id := "AEGIS-AZURE-228"
	mustFinding(t, runRule(aksNoOSAutoUpgrade{}, aksRes17(nil)), id)
	mustFinding(t, runRule(aksNoOSAutoUpgrade{}, aksRes17(map[string]ir.Value{"node_os_upgrade_channel": ks("None", 3)})), id)
	for _, good := range []string{"SecurityPatch", "NodeImage"} {
		r := aksRes17(map[string]ir.Value{"node_os_upgrade_channel": ks(good, 3)})
		if f := runRule(aksNoOSAutoUpgrade{}, r); len(f) != 0 {
			t.Fatalf("%s must not fire, got %d", good, len(f))
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-229: API server exposure
// ---------------------------------------------------------------------------

func TestAZURE229(t *testing.T) {
	id := "AEGIS-AZURE-229"
	// Non-private, no ranges -> fires
	mustFinding(t, runRule(aksAPIServerOpen{}, aksRes17(nil)), id)
	// Private cluster -> quiet
	r := aksRes17(map[string]ir.Value{"private_cluster_enabled": kv(true, 3)})
	if f := runRule(aksAPIServerOpen{}, r); len(f) != 0 {
		t.Fatalf("private cluster must not fire, got %d", len(f))
	}
	// Authorized ranges -> quiet
	r2 := aksRes17(map[string]ir.Value{
		"api_server_access_profile": blks(3, blk("authorized_ip_ranges", strList(4, "10.0.0.0/8"))),
	})
	if f := runRule(aksAPIServerOpen{}, r2); len(f) != 0 {
		t.Fatalf("authorized ranges must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-230: AAD RBAC
// ---------------------------------------------------------------------------

func TestAZURE230(t *testing.T) {
	id := "AEGIS-AZURE-230"
	mustFinding(t, runRule(aksNoAADRBAC{}, aksRes17(nil)), id)
	r := aksRes17(map[string]ir.Value{
		"azure_active_directory_role_based_access_control": blks(3, blk("tenant_id", ks("t", 4))),
	})
	if f := runRule(aksNoAADRBAC{}, r); len(f) != 0 {
		t.Fatalf("AAD RBAC present must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-232/233: LB SKU & ephemeral disk
// ---------------------------------------------------------------------------

func TestAZURE233(t *testing.T) {
	mustFinding(t, runRule(aksNoEphemeralDisk{}, aksRes17(map[string]ir.Value{
		"default_node_pool": blks(3, blk()),
	})), "AEGIS-AZURE-233")
	r2 := aksRes17(map[string]ir.Value{
		"default_node_pool": blks(3, blk("os_disk_type", ks("Ephemeral", 4))),
	})
	if f := runRule(aksNoEphemeralDisk{}, r2); len(f) != 0 {
		t.Fatalf("233: ephemeral must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-235: NSG flow log
// ---------------------------------------------------------------------------

func TestAZURE235(t *testing.T) {
	id := "AEGIS-AZURE-235"
	mustFinding(t, runRule(nsgFlowLogDisabled{}, res("azurerm_network_watcher_flow_log", "f", nil)), id)
	mustFinding(t, runRule(nsgFlowLogDisabled{}, res("azurerm_network_watcher_flow_log", "f", map[string]ir.Value{"enabled": kv(false, 3)})), id)
	r := res("azurerm_network_watcher_flow_log", "f", map[string]ir.Value{"enabled": kv(true, 3)})
	if f := runRule(nsgFlowLogDisabled{}, r); len(f) != 0 {
		t.Fatalf("enabled must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-236: Firewall threat intel
// ---------------------------------------------------------------------------

func TestAZURE236(t *testing.T) {
	id := "AEGIS-AZURE-236"
	mustFinding(t, runRule(firewallThreatIntelOff{}, res("azurerm_firewall", "f", nil)), id)
	r := res("azurerm_firewall", "f", map[string]ir.Value{"threat_intel_mode": ks("Deny", 3)})
	if f := runRule(firewallThreatIntelOff{}, r); len(f) != 0 {
		t.Fatalf("Deny must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-237: Bastion clipboard
// ---------------------------------------------------------------------------

func TestAZURE237(t *testing.T) {
	id := "AEGIS-AZURE-237"
	mustFinding(t, runRule(bastionClipboardOn{}, res("azurerm_bastion_host", "b", nil)), id)
	r := res("azurerm_bastion_host", "b", map[string]ir.Value{"copy_paste_enabled": kv(false, 3)})
	if f := runRule(bastionClipboardOn{}, r); len(f) != 0 {
		t.Fatalf("disabled must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-238: Front Door WAF mode
// ---------------------------------------------------------------------------

func TestAZURE238(t *testing.T) {
	id := "AEGIS-AZURE-238"
	f := mustFinding(t, runRule(frontdoorWAFNotPrevent{}, res("azurerm_frontdoor_firewall_policy", "w", nil)), id)
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	r := res("azurerm_frontdoor_firewall_policy", "w", map[string]ir.Value{"mode": ks("Prevention", 3)})
	if f := runRule(frontdoorWAFNotPrevent{}, r); len(f) != 0 {
		t.Fatalf("Prevention must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-239/240: App Gateway WAF & TLS
// ---------------------------------------------------------------------------

func TestAZURE239_240(t *testing.T) {
	mustFinding(t, runRule(appGWNoWAF{}, res("azurerm_application_gateway", "g", map[string]ir.Value{
		"waf_configuration": blks(3, blk()),
	})), "AEGIS-AZURE-239")
	r := res("azurerm_application_gateway", "g", map[string]ir.Value{
		"waf_configuration": blks(3, blk("enabled", kv(true, 4))),
	})
	if f := runRule(appGWNoWAF{}, r); len(f) != 0 {
		t.Fatalf("239: WAF enabled must not fire")
	}
	if f := runRule(appGWNoWAF{}, res("azurerm_application_gateway", "g", nil)); len(f) != 0 {
		t.Fatalf("239: absent waf_configuration must not fire")
	}

	mustFinding(t, runRule(appGWTLSBelow12{}, res("azurerm_application_gateway", "g", map[string]ir.Value{
		"ssl_policy": blks(3, blk("min_protocol_version", ks("TLSv1_0", 4))),
	})), "AEGIS-AZURE-240")
	r2 := res("azurerm_application_gateway", "g", map[string]ir.Value{
		"ssl_policy": blks(3, blk("min_protocol_version", ks("TLSv1_2", 4))),
	})
	if f := runRule(appGWTLSBelow12{}, r2); len(f) != 0 {
		t.Fatalf("240: TLSv1_2 must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-241/242: Basic SKUs
// ---------------------------------------------------------------------------

func TestAZURE241_242(t *testing.T) {
	mustFinding(t, runRule(publicIPBasicSKU{}, res("azurerm_public_ip", "p", map[string]ir.Value{"sku": ks("Basic", 3)})), "AEGIS-AZURE-241")
	r := res("azurerm_public_ip", "p", map[string]ir.Value{"sku": ks("Standard", 3)})
	if f := runRule(publicIPBasicSKU{}, r); len(f) != 0 {
		t.Fatalf("241: Standard must not fire")
	}
	if f := runRule(publicIPBasicSKU{}, res("azurerm_public_ip", "p", nil)); len(f) != 0 {
		t.Fatalf("241: absent must not fire")
	}
	mustFinding(t, runRule(lbBasicSKU{}, res("azurerm_lb", "l", map[string]ir.Value{"sku": ks("Basic", 3)})), "AEGIS-AZURE-242")
	r2 := res("azurerm_lb", "l", map[string]ir.Value{"sku": ks("Standard", 3)})
	if f := runRule(lbBasicSKU{}, r2); len(f) != 0 {
		t.Fatalf("242: Standard must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-057: VNet DDoS plan
// ---------------------------------------------------------------------------

func TestAZURE057(t *testing.T) {
	id := "AEGIS-AZURE-057"
	mustFinding(t, runRule(vnetNoDDoS{}, res("azurerm_virtual_network", "v", nil)), id)
	r := res("azurerm_virtual_network", "v", map[string]ir.Value{
		"ddos_protection_plan": blks(3, blk("id", ks("x", 4), "enable", kv(true, 4))),
	})
	if f := runRule(vnetNoDDoS{}, r); len(f) != 0 {
		t.Fatalf("enabled plan must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-244: NSG inline open rule
// ---------------------------------------------------------------------------

func TestAZURE244(t *testing.T) {
	id := "AEGIS-AZURE-244"
	r := res("azurerm_network_security_group", "n", map[string]ir.Value{
		"security_rule": blks(3,
			blk("direction", ks("Inbound", 4), "access", ks("Allow", 4), "source_address_prefix", ks("*", 4))),
	})
	f := mustFinding(t, runRule(nsgInlineOpenRule{}, r), id)
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	r2 := res("azurerm_network_security_group", "n", map[string]ir.Value{
		"security_rule": blks(3,
			blk("direction", ks("Inbound", 4), "access", ks("Allow", 4), "source_address_prefix", ks("10.0.0.0/8", 4))),
	})
	if f := runRule(nsgInlineOpenRule{}, r2); len(f) != 0 {
		t.Fatalf("restricted inline rule must not fire, got %d", len(f))
	}
	if f := runRule(nsgInlineOpenRule{}, res("azurerm_network_security_group", "n", nil)); len(f) != 0 {
		t.Fatalf("no inline rules must not fire, got %d", len(f))
	}
}
