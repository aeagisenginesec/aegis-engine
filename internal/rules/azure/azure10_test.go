package azure

import (
	"testing"

	"aegis/internal/ir"
)

func aksRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_kubernetes_cluster", "c", attrs)
}

// AEGIS-AZURE-127: local accounts
func TestAZURE127_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(aksLocalAccountsEnabled{}, aksRes(nil)), "AEGIS-AZURE-127")
}

func TestAZURE127_FalseFires(t *testing.T) {
	r := aksRes(map[string]ir.Value{"local_account_disabled": kv(false, 3)})
	mustFinding(t, runRule(aksLocalAccountsEnabled{}, r), "AEGIS-AZURE-127")
}

func TestAZURE127_DisabledQuiet(t *testing.T) {
	r := aksRes(map[string]ir.Value{"local_account_disabled": kv(true, 3)})
	if len(runRule(aksLocalAccountsEnabled{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE127_UnknownQuiet(t *testing.T) {
	r := aksRes(map[string]ir.Value{"local_account_disabled": ku(3)})
	if len(runRule(aksLocalAccountsEnabled{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-128: Azure AD RBAC integration
func TestAZURE128_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(aksNoAADIntegration{}, aksRes(nil)), "AEGIS-AZURE-128")
}

func TestAZURE128_UnmanagedFires(t *testing.T) {
	r := aksRes(map[string]ir.Value{
		"azure_active_directory_role_based_access_control": blks(3, blk("managed", kv(false, 4))),
	})
	mustFinding(t, runRule(aksNoAADIntegration{}, r), "AEGIS-AZURE-128")
}

func TestAZURE128_ManagedQuiet(t *testing.T) {
	r := aksRes(map[string]ir.Value{
		"azure_active_directory_role_based_access_control": blks(3, blk("managed", kv(true, 4))),
	})
	if len(runRule(aksNoAADIntegration{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-129: Key Vault secrets provider
func TestAZURE129_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(aksNoKVSecretsProvider{}, aksRes(nil)), "AEGIS-AZURE-129")
}

func TestAZURE129_PresentQuiet(t *testing.T) {
	r := aksRes(map[string]ir.Value{
		"key_vault_secrets_provider": blks(3, blk("secret_rotation_enabled", kv(true, 4))),
	})
	if len(runRule(aksNoKVSecretsProvider{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-130: Microsoft Defender
func TestAZURE130_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(aksNoDefender{}, aksRes(nil)), "AEGIS-AZURE-130")
}

func TestAZURE130_PresentQuiet(t *testing.T) {
	r := aksRes(map[string]ir.Value{
		"microsoft_defender": blks(3, blk("log_analytics_workspace_id", ks("x", 4))),
	})
	if len(runRule(aksNoDefender{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-131: image cleaner
func TestAZURE131_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(aksNoImageCleaner{}, aksRes(nil)), "AEGIS-AZURE-131")
}

func TestAZURE131_EnabledQuiet(t *testing.T) {
	r := aksRes(map[string]ir.Value{"image_cleaner_enabled": kv(true, 3)})
	if len(runRule(aksNoImageCleaner{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-132: node OS auto-upgrade channel
func TestAZURE132_AbsentFires(t *testing.T) {
	r := aksRes(map[string]ir.Value{"default_node_pool": blks(3, blk("name", ks("default", 4)))})
	mustFinding(t, runRule(aksNoNodeOSAutoUpgrade{}, r), "AEGIS-AZURE-132")
}

func TestAZURE132_NoneFires(t *testing.T) {
	r := aksRes(map[string]ir.Value{
		"default_node_pool": blks(3, blk("node_os_upgrade_channel", ks("None", 4))),
	})
	mustFinding(t, runRule(aksNoNodeOSAutoUpgrade{}, r), "AEGIS-AZURE-132")
}

func TestAZURE132_SecurityPatchQuiet(t *testing.T) {
	r := aksRes(map[string]ir.Value{
		"default_node_pool": blks(3, blk("node_os_upgrade_channel", ks("SecurityPatch", 4))),
	})
	if len(runRule(aksNoNodeOSAutoUpgrade{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-133: host encryption
func TestAZURE133_AbsentFires(t *testing.T) {
	r := aksRes(map[string]ir.Value{"default_node_pool": blks(3, blk("name", ks("default", 4)))})
	mustFinding(t, runRule(aksNoHostEncryption{}, r), "AEGIS-AZURE-133")
}

func TestAZURE133_EnabledQuiet(t *testing.T) {
	r := aksRes(map[string]ir.Value{
		"default_node_pool": blks(3, blk("host_encryption_enabled", kv(true, 4))),
	})
	if len(runRule(aksNoHostEncryption{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-134: cost analysis
func TestAZURE134_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(aksNoCostAnalysis{}, aksRes(nil)), "AEGIS-AZURE-134")
}

func TestAZURE134_EnabledQuiet(t *testing.T) {
	r := aksRes(map[string]ir.Value{"cost_analysis_enabled": kv(true, 3)})
	if len(runRule(aksNoCostAnalysis{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-135: upgrade channel strict (absent)
func TestAZURE135_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(aksNoUpgradeChannelStrict{}, aksRes(nil)), "AEGIS-AZURE-135")
}

func TestAZURE135_PresentQuiet(t *testing.T) {
	// Present (none or a real channel) is AEGIS-AZURE-073's domain.
	for _, ch := range []string{"none", "patch", "stable"} {
		r := aksRes(map[string]ir.Value{"automatic_upgrade_channel": ks(ch, 3)})
		if len(runRule(aksNoUpgradeChannelStrict{}, r)) != 0 {
			t.Fatalf("expected 0 findings for %q", ch)
		}
	}
}

// AEGIS-AZURE-136: OIDC issuer strict (absent)
func TestAZURE136_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(aksNoOIDCIssuerStrict{}, aksRes(nil)), "AEGIS-AZURE-136")
}

func TestAZURE136_PresentQuiet(t *testing.T) {
	// Present (true or false) is AEGIS-AZURE-076's domain.
	for _, v := range []bool{true, false} {
		r := aksRes(map[string]ir.Value{"oidc_issuer_enabled": kv(v, 3)})
		if len(runRule(aksNoOIDCIssuerStrict{}, r)) != 0 {
			t.Fatal("expected 0 findings")
		}
	}
}

// Azure10Rules returns all 10 in ID order.
func TestAzure10RulesInIDOrder(t *testing.T) {
	rules := Azure10Rules()
	if len(rules) != 10 {
		t.Fatalf("expected 10 rules, got %d", len(rules))
	}
	want := "AEGIS-AZURE-127"
	for i, r := range rules {
		if i == 0 && r.ID() != want {
			t.Fatalf("first rule: want %s, got %s", want, r.ID())
		}
		if r.ID() == "" || r.Title() == "" || r.Description() == "" {
			t.Fatalf("rule %d missing metadata", i)
		}
	}
	if rules[9].ID() != "AEGIS-AZURE-136" {
		t.Fatalf("last rule: want AEGIS-AZURE-136, got %s", rules[9].ID())
	}
}
