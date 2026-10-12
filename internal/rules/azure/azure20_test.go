package azure

import (
	"strconv"
	"testing"

	"aegis/internal/ir"
)

// Pack registration: Azure20Rules must be wired into Rules() in ID order.
func TestAzure20RegisteredInIDOrder(t *testing.T) {
	rules := Rules()
	idx := map[string]int{}
	for i, r := range rules {
		idx[r.ID()] = i
	}
	for n := 282; n <= 297; n++ {
		id := "AEGIS-AZURE-" + strconv.Itoa(n)
		i, ok := idx[id]
		if !ok {
			t.Fatalf("rule %s not registered", id)
		}
		if n > 282 {
			prev := "AEGIS-AZURE-" + strconv.Itoa(n-1)
			if idx[prev] != i-1 {
				t.Fatalf("rules out of order: %s at %d, %s at %d", prev, idx[prev], id, i)
			}
		}
	}
}

func rsvRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_recovery_services_vault", "v", attrs)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-282..285: Front Door family
// ---------------------------------------------------------------------------

func TestAZURE282_285(t *testing.T) {
	mustFinding(t, runRule(fdWAFNoManagedRule{}, res("azurerm_frontdoor_firewall_policy", "w", nil)), "AEGIS-AZURE-282")
	r := res("azurerm_frontdoor_firewall_policy", "w", map[string]ir.Value{
		"managed_rule": blks(3, blk("type", ks("DefaultRuleSet", 4))),
	})
	if f := runRule(fdWAFNoManagedRule{}, r); len(f) != 0 {
		t.Fatalf("282: managed rule present must not fire")
	}

	mustFinding(t, runRule(fdWAFNoCustomRule{}, res("azurerm_frontdoor_firewall_policy", "w", nil)), "AEGIS-AZURE-283")
	r2 := res("azurerm_frontdoor_firewall_policy", "w", map[string]ir.Value{
		"custom_rule": blks(3, blk("name", ks("r1", 4))),
	})
	if f := runRule(fdWAFNoCustomRule{}, r2); len(f) != 0 {
		t.Fatalf("283: custom rule present must not fire")
	}

	mustFinding(t, runRule(fdOriginWeakTLS{}, res("azurerm_frontdoor", "f", map[string]ir.Value{
		"backend_pool_health_probe": blks(3, blk("protocol", ks("Http", 4))),
	})), "AEGIS-AZURE-284")
	r3 := res("azurerm_frontdoor", "f", map[string]ir.Value{
		"backend_pool_health_probe": blks(3, blk("protocol", ks("Https", 4))),
	})
	if f := runRule(fdOriginWeakTLS{}, r3); len(f) != 0 {
		t.Fatalf("284: Https probe must not fire")
	}

	mustFinding(t, runRule(fdNoHTTPSRedirect{}, res("azurerm_frontdoor", "f", nil)), "AEGIS-AZURE-285")
	r4 := res("azurerm_frontdoor", "f", map[string]ir.Value{
		"routing_rule": blks(3, blk("redirect_configuration", ir.Value{
			Raw:   map[string]ir.Value{"redirect_type": ks("Found", 5)},
			Known: true, Span: spanAt(4),
		})),
	})
	if f := runRule(fdNoHTTPSRedirect{}, r4); len(f) != 0 {
		t.Fatalf("285: redirect rule must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-286/287: CDN family
// ---------------------------------------------------------------------------

func TestAZURE286_287(t *testing.T) {
	mustFinding(t, runRule(cdnNoHTTPS{}, res("azurerm_cdn_endpoint", "c", nil)), "AEGIS-AZURE-286")
	r := res("azurerm_cdn_endpoint", "c", map[string]ir.Value{"is_https_allowed": kv(true, 3)})
	if f := runRule(cdnNoHTTPS{}, r); len(f) != 0 {
		t.Fatalf("286: https allowed must not fire")
	}

	mustFinding(t, runRule(cdnWeakTLS{}, res("azurerm_cdn_endpoint", "c", map[string]ir.Value{"minimum_tls_version": ks("TLS10", 3)})), "AEGIS-AZURE-287")
	r2 := res("azurerm_cdn_endpoint", "c", map[string]ir.Value{"minimum_tls_version": ks("TLS12", 3)})
	if f := runRule(cdnWeakTLS{}, r2); len(f) != 0 {
		t.Fatalf("287: TLS12 must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-288..291: Recovery vault family
// ---------------------------------------------------------------------------

func TestAZURE288_291(t *testing.T) {
	f := mustFinding(t, runRule(backupSoftDeleteOff{}, rsvRes(nil)), "AEGIS-AZURE-288")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("288: wrong severity %s", f.Severity)
	}
	r := rsvRes(map[string]ir.Value{"soft_delete_enabled": kv(true, 3)})
	if f := runRule(backupSoftDeleteOff{}, r); len(f) != 0 {
		t.Fatalf("288: enabled must not fire")
	}

	mustFinding(t, runRule(backupNoCMK{}, rsvRes(nil)), "AEGIS-AZURE-289")
	r2 := rsvRes(map[string]ir.Value{"customer_managed_key_id": ks("k", 3)})
	if f := runRule(backupNoCMK{}, r2); len(f) != 0 {
		t.Fatalf("289: CMK set must not fire")
	}

	f = mustFinding(t, runRule(backupNoImmutability{}, rsvRes(nil)), "AEGIS-AZURE-290")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("290: wrong severity %s", f.Severity)
	}
	r3 := rsvRes(map[string]ir.Value{"immutability": ks("Locked", 3)})
	if f := runRule(backupNoImmutability{}, r3); len(f) != 0 {
		t.Fatalf("290: Locked must not fire")
	}

	mustFinding(t, runRule(backupNoXRegion{}, rsvRes(nil)), "AEGIS-AZURE-291")
	r4 := rsvRes(map[string]ir.Value{"cross_region_restore_enabled": kv(true, 3)})
	if f := runRule(backupNoXRegion{}, r4); len(f) != 0 {
		t.Fatalf("291: enabled must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-292/293: Automation family
// ---------------------------------------------------------------------------

func TestAZURE292_293(t *testing.T) {
	mustFinding(t, runRule(automationNoIdentity{}, res("azurerm_automation_account", "a", nil)), "AEGIS-AZURE-292")
	r := res("azurerm_automation_account", "a", map[string]ir.Value{
		"identity": blks(3, blk("type", ks("SystemAssigned", 4))),
	})
	if f := runRule(automationNoIdentity{}, r); len(f) != 0 {
		t.Fatalf("292: identity present must not fire")
	}

	mustFinding(t, runRule(automationVarUnenc{}, res("azurerm_automation_variable_string", "v", nil)), "AEGIS-AZURE-293")
	r2 := res("azurerm_automation_variable_string", "v", map[string]ir.Value{"encrypted": kv(true, 3)})
	if f := runRule(automationVarUnenc{}, r2); len(f) != 0 {
		t.Fatalf("293: encrypted must not fire")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-294..297: VM family
// ---------------------------------------------------------------------------

func TestAZURE294_297(t *testing.T) {
	mustFinding(t, runRule(vmNoHostEncryption{}, res("azurerm_linux_virtual_machine", "v", nil)), "AEGIS-AZURE-294")
	r := res("azurerm_linux_virtual_machine", "v", map[string]ir.Value{"encryption_at_host_enabled": kv(true, 3)})
	if f := runRule(vmNoHostEncryption{}, r); len(f) != 0 {
		t.Fatalf("294: enabled must not fire")
	}

	mustFinding(t, runRule(vmNoSecureBoot{}, res("azurerm_linux_virtual_machine", "v", nil)), "AEGIS-AZURE-295")
	r2 := res("azurerm_linux_virtual_machine", "v", map[string]ir.Value{"secure_boot_enabled": kv(true, 3)})
	if f := runRule(vmNoSecureBoot{}, r2); len(f) != 0 {
		t.Fatalf("295: enabled must not fire")
	}

	mustFinding(t, runRule(vmUnmanagedDisk{}, res("azurerm_virtual_machine", "v", map[string]ir.Value{
		"storage_os_disk": blks(3, blk("vhd_uri", ks("https://x.blob.core.windows.net/vhds/os.vhd", 4))),
	})), "AEGIS-AZURE-296")
	if f := runRule(vmUnmanagedDisk{}, res("azurerm_virtual_machine", "v", nil)); len(f) != 0 {
		t.Fatalf("296: no storage_os_disk must not fire")
	}

	mustFinding(t, runRule(vmNoBootDiag{}, res("azurerm_linux_virtual_machine", "v", nil)), "AEGIS-AZURE-297")
	r3 := res("azurerm_linux_virtual_machine", "v", map[string]ir.Value{
		"boot_diagnostics": blks(3, blk("storage_account_uri", ks("https://x.blob.core.windows.net/", 4))),
	})
	if f := runRule(vmNoBootDiag{}, r3); len(f) != 0 {
		t.Fatalf("297: boot diagnostics present must not fire")
	}
}
