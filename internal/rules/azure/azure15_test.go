package azure

import (
	"strconv"
	"testing"

	"aegis/internal/ir"
)

// kn builds a known numeric value (float64, as the adapter produces).
func kn(f float64, line int) ir.Value {
	return ir.Value{Raw: f, Known: true, Span: spanAt(line)}
}

// Pack registration: Azure15Rules must be wired into Rules() in ID order.
func TestAzure15RegisteredInIDOrder(t *testing.T) {
	rules := Rules()
	idx := map[string]int{}
	for i, r := range rules {
		idx[r.ID()] = i
	}
	// 188,190,193,196,198,202,203 removed as post-audit duplicates.
	want := []int{186, 187, 189, 191, 192, 194, 195, 197, 199, 200, 201, 204, 205}
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

// ---------------------------------------------------------------------------
// AEGIS-AZURE-186: Key Vault soft-delete retention under 90 days
// ---------------------------------------------------------------------------

func TestAZURE186(t *testing.T) {
	id := "AEGIS-AZURE-186"
	mustFinding(t, runRule(kvSoftDeleteRetention{}, res("azurerm_key_vault", "v", map[string]ir.Value{"soft_delete_retention_days": kn(7, 3)})), id)
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"soft_delete_retention_days": kn(90, 3)})
	if f := runRule(kvSoftDeleteRetention{}, r); len(f) != 0 {
		t.Fatalf("90 days must not fire, got %d", len(f))
	}
	if f := runRule(kvSoftDeleteRetention{}, res("azurerm_key_vault", "v", nil)); len(f) != 0 {
		t.Fatalf("absent must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-187: Key Vault network ACLs allow public traffic
// ---------------------------------------------------------------------------

func TestAZURE187(t *testing.T) {
	id := "AEGIS-AZURE-187"
	mustFinding(t, runRule(kvNetworkAclsOpen{}, res("azurerm_key_vault", "v", nil)), id)
	r := res("azurerm_key_vault", "v", map[string]ir.Value{
		"network_acls": blks(3, blk("default_action", ks("Allow", 4))),
	})
	mustFinding(t, runRule(kvNetworkAclsOpen{}, r), id)
	r2 := res("azurerm_key_vault", "v", map[string]ir.Value{
		"network_acls": blks(3, blk("default_action", ks("Deny", 4))),
	})
	if f := runRule(kvNetworkAclsOpen{}, r2); len(f) != 0 {
		t.Fatalf("Deny must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-188: Key Vault not using RBAC authorization
// ---------------------------------------------------------------------------

func TestAZURE038(t *testing.T) {
	id := "AEGIS-AZURE-038"
	mustFinding(t, runRule(keyVaultNoRBAC{}, res("azurerm_key_vault", "v", nil)), id)
	mustFinding(t, runRule(keyVaultNoRBAC{}, res("azurerm_key_vault", "v", map[string]ir.Value{"enable_rbac_authorization": kv(false, 3)})), id)
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"enable_rbac_authorization": kv(true, 3)})
	if f := runRule(keyVaultNoRBAC{}, r); len(f) != 0 {
		t.Fatalf("RBAC enabled must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-189: Key Vault key not HSM-backed
// ---------------------------------------------------------------------------

func TestAZURE189(t *testing.T) {
	id := "AEGIS-AZURE-189"
	mustFinding(t, runRule(kvKeyNotHSM{}, res("azurerm_key_vault_key", "k", map[string]ir.Value{"key_type": ks("RSA", 3)})), id)
	r := res("azurerm_key_vault_key", "k", map[string]ir.Value{"key_type": ks("RSA-HSM", 3)})
	if f := runRule(kvKeyNotHSM{}, r); len(f) != 0 {
		t.Fatalf("HSM key must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-040: Key Vault secret without expiration date (consolidated from 190)
// ---------------------------------------------------------------------------

func TestAZURE040(t *testing.T) {
	id := "AEGIS-AZURE-040"
	mustFinding(t, runRule(keyVaultSecretNoExpiry{}, res("azurerm_key_vault_secret", "s", nil)), id)
	r := res("azurerm_key_vault_secret", "s", map[string]ir.Value{"expiration_date": ks("2027-01-01T00:00:00Z", 3)})
	if f := runRule(keyVaultSecretNoExpiry{}, r); len(f) != 0 {
		t.Fatalf("dated secret must not fire, got %d", len(f))
	}
	// Empty string also fires (ported from 190)
	e := res("azurerm_key_vault_secret", "s", map[string]ir.Value{"expiration_date": ks("", 3)})
	mustFinding(t, runRule(keyVaultSecretNoExpiry{}, e), id)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-191..193,195,196: storage boolean family
// ---------------------------------------------------------------------------

func TestAZURE191_193_195_196(t *testing.T) {
	cases := []struct {
		rule ir.Rule
		id   string
		attr string
		// fireWhenTrue: finding when attr true (or absent if absentFires)
		fireWhenTrue bool
		absentFires  bool
	}{
		{storageSharedKeyEnabled{}, "AEGIS-AZURE-191", "shared_access_key_enabled", true, true},
		{storageNoOAuthDefault{}, "AEGIS-AZURE-192", "default_to_oauth_authentication", false, true},
		{storageNestedPublic{}, "AEGIS-AZURE-195", "allow_nested_items_to_be_public", true, true},
		{storageNoInfraEncryption{}, "AEGIS-AZURE-032", "infrastructure_encryption_enabled", false, true},
		{storageSFTPEnabled{}, "AEGIS-AZURE-204", "sftp_enabled", true, false},
	}
	for _, c := range cases {
		if c.absentFires {
			mustFinding(t, runRule(c.rule, res("azurerm_storage_account", "s", nil)), c.id)
		} else if f := runRule(c.rule, res("azurerm_storage_account", "s", nil)); len(f) != 0 {
			t.Fatalf("%s: absent must not fire", c.id)
		}
		mustFinding(t, runRule(c.rule, res("azurerm_storage_account", "s", map[string]ir.Value{c.attr: kv(c.fireWhenTrue, 3)})), c.id)
		if f := runRule(c.rule, res("azurerm_storage_account", "s", map[string]ir.Value{c.attr: kv(!c.fireWhenTrue, 3)})); len(f) != 0 {
			t.Fatalf("%s: secure value must not fire", c.id)
		}
		if f := runRule(c.rule, res("azurerm_storage_account", "s", map[string]ir.Value{c.attr: ku(3)})); len(f) != 0 {
			t.Fatalf("%s: unknown must not fire", c.id)
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-029: Storage account without blob soft delete
// ---------------------------------------------------------------------------

func TestAZURE029(t *testing.T) {
	id := "AEGIS-AZURE-029"
	mustFinding(t, runRule(storageNoBlobSoftDelete{}, res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk()),
	})), id)
	mustFinding(t, runRule(storageNoBlobSoftDelete{}, res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk("delete_retention_policy", blks(4, blk("days", kn(0, 5))))),
	})), id)
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk("delete_retention_policy", blks(4, blk("days", kn(7, 5))))),
	})
	if f := runRule(storageNoBlobSoftDelete{}, r); len(f) != 0 {
		t.Fatalf("soft delete enabled must not fire, got %d", len(f))
	}
	// Absent blob_properties fires (soft delete not configured).
	mustFinding(t, runRule(storageNoBlobSoftDelete{}, res("azurerm_storage_account", "s", nil)), "AEGIS-AZURE-029")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-194: Storage SAS policy not blocking on expiry
// ---------------------------------------------------------------------------

func TestAZURE194(t *testing.T) {
	id := "AEGIS-AZURE-194"
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"sas_policy": blks(3, blk("expiration_action", ks("Log", 4))),
	})
	mustFinding(t, runRule(storageSasNotBlocked{}, r), id)
	r2 := res("azurerm_storage_account", "s", map[string]ir.Value{
		"sas_policy": blks(3, blk("expiration_action", ks("Block", 4))),
	})
	if f := runRule(storageSasNotBlocked{}, r2); len(f) != 0 {
		t.Fatalf("Block must not fire, got %d", len(f))
	}
	if f := runRule(storageSasNotBlocked{}, res("azurerm_storage_account", "s", nil)); len(f) != 0 {
		t.Fatalf("absent sas_policy must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-197: Storage container not private
// ---------------------------------------------------------------------------

func TestAZURE197(t *testing.T) {
	id := "AEGIS-AZURE-197"
	mustFinding(t, runRule(storageContainerPublic{}, res("azurerm_storage_container", "c", map[string]ir.Value{"container_access_type": ks("blob", 3)})), id)
	mustFinding(t, runRule(storageContainerPublic{}, res("azurerm_storage_container", "c", map[string]ir.Value{"container_access_type": ks("container", 3)})), id)
	r := res("azurerm_storage_container", "c", map[string]ir.Value{"container_access_type": ks("private", 3)})
	if f := runRule(storageContainerPublic{}, r); len(f) != 0 {
		t.Fatalf("private must not fire, got %d", len(f))
	}
	if f := runRule(storageContainerPublic{}, res("azurerm_storage_container", "c", nil)); len(f) != 0 {
		t.Fatalf("absent (default private) must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-030: Storage account without container soft delete
// ---------------------------------------------------------------------------

func TestAZURE030(t *testing.T) {
	id := "AEGIS-AZURE-030"
	mustFinding(t, runRule(storageNoContainerDelete{}, res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk()),
	})), id)
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk("container_delete_retention_policy", blks(4, blk("days", kn(7, 5))))),
	})
	if f := runRule(storageNoContainerDelete{}, r); len(f) != 0 {
		t.Fatalf("container soft delete must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-199: Storage network rules allow public traffic
// ---------------------------------------------------------------------------

func TestAZURE199(t *testing.T) {
	id := "AEGIS-AZURE-199"
	mustFinding(t, runRule(storageNetRulesOpen{}, res("azurerm_storage_account_network_rules", "n", map[string]ir.Value{"default_action": ks("Allow", 3)})), id)
	r := res("azurerm_storage_account_network_rules", "n", map[string]ir.Value{"default_action": ks("Deny", 3)})
	if f := runRule(storageNetRulesOpen{}, r); len(f) != 0 {
		t.Fatalf("Deny must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-200: Key Vault key without expiration date
// ---------------------------------------------------------------------------

func TestAZURE200(t *testing.T) {
	id := "AEGIS-AZURE-200"
	mustFinding(t, runRule(kvKeyNearExpiry{}, res("azurerm_key_vault_key", "k", nil)), id)
	r := res("azurerm_key_vault_key", "k", map[string]ir.Value{"expiration_date": ks("2027-01-01T00:00:00Z", 3)})
	if f := runRule(kvKeyNearExpiry{}, r); len(f) != 0 {
		t.Fatalf("dated key must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-201: Storage account with static website hosting
// ---------------------------------------------------------------------------

func TestAZURE201(t *testing.T) {
	id := "AEGIS-AZURE-201"
	mustFinding(t, runRule(storageStaticWebsite{}, res("azurerm_storage_account", "s", map[string]ir.Value{
		"static_website": blks(3, blk("index_document", ks("index.html", 4))),
	})), id)
	if f := runRule(storageStaticWebsite{}, res("azurerm_storage_account", "s", nil)); len(f) != 0 {
		t.Fatalf("absent static_website must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-202: Key Vault certificate without lifetime actions
// ---------------------------------------------------------------------------

func TestAZURE042(t *testing.T) {
	id := "AEGIS-AZURE-042"
	mustFinding(t, runRule(keyVaultCertNoAutoRenew{}, res("azurerm_key_vault_certificate", "c", map[string]ir.Value{
		"certificate_policy": blks(3, blk()),
	})), id)
	r := res("azurerm_key_vault_certificate", "c", map[string]ir.Value{
		"certificate_policy": blks(3, blk("lifetime_action", blks(4, blk("action", ks("AutoRenew", 5))))),
	})
	if f := runRule(keyVaultCertNoAutoRenew{}, r); len(f) != 0 {
		t.Fatalf("AutoRenew present must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-028: Storage blob without versioning
// ---------------------------------------------------------------------------

func TestAZURE028b(t *testing.T) {
	id := "AEGIS-AZURE-028"
	mustFinding(t, runRule(storageNoBlobVersioning{}, res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk()),
	})), id)
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk("versioning_enabled", kv(true, 4))),
	})
	if f := runRule(storageNoBlobVersioning{}, r); len(f) != 0 {
		t.Fatalf("versioning enabled must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-205: Key Vault firewall without IP rules
// ---------------------------------------------------------------------------

func TestAZURE205(t *testing.T) {
	id := "AEGIS-AZURE-205"
	// Deny with no allowances -> fires
	r := res("azurerm_key_vault", "v", map[string]ir.Value{
		"network_acls": blks(3, blk("default_action", ks("Deny", 4))),
	})
	mustFinding(t, runRule(kvNoFirewallRules{}, r), id)
	// Deny with an IP allowance -> quiet
	r2 := res("azurerm_key_vault", "v", map[string]ir.Value{
		"network_acls": blks(3, blk("default_action", ks("Deny", 4), "ip_rules", strList(5, "10.0.0.0/8"))),
	})
	if f := runRule(kvNoFirewallRules{}, r2); len(f) != 0 {
		t.Fatalf("Deny with ip_rules must not fire, got %d", len(f))
	}
	// Allow default -> 187's territory, not 205's
	r3 := res("azurerm_key_vault", "v", map[string]ir.Value{
		"network_acls": blks(3, blk("default_action", ks("Allow", 4))),
	})
	if f := runRule(kvNoFirewallRules{}, r3); len(f) != 0 {
		t.Fatalf("Allow default must not fire 205, got %d", len(f))
	}
}
