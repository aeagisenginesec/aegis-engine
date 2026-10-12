package azure

import (
	"testing"

	"aegis/internal/ir"
)

func saRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_storage_account", "sa", attrs)
}

// AEGIS-AZURE-144: infrastructure encryption
func TestAZURE032_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(storageNoInfraEncryption{}, saRes(nil)), "AEGIS-AZURE-032")
}

func TestAZURE032_EnabledQuiet(t *testing.T) {
	r := saRes(map[string]ir.Value{"infrastructure_encryption_enabled": kv(true, 3)})
	if len(runRule(storageNoInfraEncryption{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-145: cross-tenant replication
func TestAZURE145_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(storageCrossTenantRepl{}, saRes(nil)), "AEGIS-AZURE-145")
}

func TestAZURE145_TrueFires(t *testing.T) {
	r := saRes(map[string]ir.Value{"allow_cross_tenant_replication": kv(true, 3)})
	mustFinding(t, runRule(storageCrossTenantRepl{}, r), "AEGIS-AZURE-145")
}

func TestAZURE145_DisabledQuiet(t *testing.T) {
	r := saRes(map[string]ir.Value{"allow_cross_tenant_replication": kv(false, 3)})
	if len(runRule(storageCrossTenantRepl{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-028: blob versioning
func TestAZURE028_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(storageNoBlobVersioning{}, saRes(nil)), "AEGIS-AZURE-028")
}

func TestAZURE028_EnabledQuiet(t *testing.T) {
	r := saRes(map[string]ir.Value{
		"blob_properties": blks(3, blk("versioning_enabled", kv(true, 4))),
	})
	if len(runRule(storageNoBlobVersioning{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-147: change feed
func TestAZURE147_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(storageNoChangeFeed{}, saRes(nil)), "AEGIS-AZURE-147")
}

func TestAZURE147_EnabledQuiet(t *testing.T) {
	r := saRes(map[string]ir.Value{
		"blob_properties": blks(3, blk("change_feed_enabled", kv(true, 4))),
	})
	if len(runRule(storageNoChangeFeed{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-148: public network access strict (absent)
func TestAZURE148_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(storagePublicNetStrict{}, saRes(nil)), "AEGIS-AZURE-148")
}

func TestAZURE148_PresentQuiet(t *testing.T) {
	// Present (true or false) is AEGIS-AZURE-006's domain.
	for _, v := range []bool{true, false} {
		r := saRes(map[string]ir.Value{"public_network_access_enabled": kv(v, 3)})
		if len(runRule(storagePublicNetStrict{}, r)) != 0 {
			t.Fatal("expected 0 findings")
		}
	}
}

// AEGIS-AZURE-149: network rules strict (absent)
func TestAZURE149_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(storageNoNetworkRules{}, saRes(nil)), "AEGIS-AZURE-149")
}

func TestAZURE149_DenyQuiet(t *testing.T) {
	r := saRes(map[string]ir.Value{
		"network_rules": blks(3, blk("default_action", ks("Deny", 4))),
	})
	if len(runRule(storageNoNetworkRules{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE149_AllowQuiet(t *testing.T) {
	// Explicit Allow is AEGIS-AZURE-021's finding, not this rule's.
	r := saRes(map[string]ir.Value{
		"network_rules": blks(3, blk("default_action", ks("Allow", 4))),
	})
	if len(runRule(storageNoNetworkRules{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// Azure12Rules returns all 6 in ID order.
func TestAzure12RulesInIDOrder(t *testing.T) {
	rules := Azure12Rules()
	// 4 rules after post-audit dedup removed 144, 146 (duplicates of 032, 028).
	if len(rules) != 4 {
		t.Fatalf("expected 4 rules, got %d", len(rules))
	}
	if rules[0].ID() != "AEGIS-AZURE-145" || rules[3].ID() != "AEGIS-AZURE-149" {
		t.Fatalf("ID order broken: %s .. %s", rules[0].ID(), rules[3].ID())
	}
}
