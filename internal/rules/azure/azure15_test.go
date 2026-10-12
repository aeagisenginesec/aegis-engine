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
	for n := 186; n <= 205; n++ {
		id := "AEGIS-AZURE-" + strconv.Itoa(n)
		i, ok := idx[id]
		if !ok {
			t.Fatalf("rule %s not registered", id)
		}
		if n > 186 {
			prev := "AEGIS-AZURE-" + strconv.Itoa(n-1)
			if idx[prev] != i-1 {
				t.Fatalf("rules out of order: %s at %d, %s at %d", prev, idx[prev], id, i)
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

func TestAZURE188(t *testing.T) {
	id := "AEGIS-AZURE-188"
	mustFinding(t, runRule(kvNoRbacAuth{}, res("azurerm_key_vault", "v", nil)), id)
	mustFinding(t, runRule(kvNoRbacAuth{}, res("azurerm_key_vault", "v", map[string]ir.Value{"enable_rbac_authorization": kv(false, 3)})), id)
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"enable_rbac_authorization": kv(true, 3)})
	if f := runRule(kvNoRbacAuth{}, r); len(f) != 0 {
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
// AEGIS-AZURE-190: Key Vault secret without expiration date
// ---------------------------------------------------------------------------

func TestAZURE190(t *testing.T) {
	id := "AEGIS-AZURE-190"
	mustFinding(t, runRule(kvSecretNoExpiry{}, res("azurerm_key_vault_secret", "s", nil)), id)
	r := res("azurerm_key_vault_secret", "s", map[string]ir.Value{"expiration_date": ks("2027-01-01T00:00:00Z", 3)})
	if f := runRule(kvSecretNoExpiry{}, r); len(f) != 0 {
		t.Fatalf("dated secret must not fire, got %d", len(f))
	}
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
		{storageNoInfraEncrypt{}, "AEGIS-AZURE-196", "infrastructure_encryption_enabled", false, true},
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
// AEGIS-AZURE-193: Storage account without blob soft delete
// ---------------------------------------------------------------------------

func TestAZURE193(t *testing.T) {
	id := "AEGIS-AZURE-193"
	mustFinding(t, runRule(storageBlobSoftDelete{}, res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk()),
	})), id)
	mustFinding(t, runRule(storageBlobSoftDelete{}, res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk("delete_retention_policy", blks(4, blk("days", kn(0, 5))))),
	})), id)
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk("delete_retention_policy", blks(4, blk("days", kn(7, 5))))),
	})
	if f := runRule(storageBlobSoftDelete{}, r); len(f) != 0 {
		t.Fatalf("soft delete enabled must not fire, got %d", len(f))
	}
	if f := runRule(storageBlobSoftDelete{}, res("azurerm_storage_account", "s", nil)); len(f) != 0 {
		t.Fatalf("absent blob_properties must not fire, got %d", len(f))
	}
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
// AEGIS-AZURE-198: Storage account without container soft delete
// ---------------------------------------------------------------------------

func TestAZURE198(t *testing.T) {
	id := "AEGIS-AZURE-198"
	mustFinding(t, runRule(storageContainerSoftDel{}, res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk()),
	})), id)
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk("container_delete_retention_policy", blks(4, blk("days", kn(7, 5))))),
	})
	if f := runRule(storageContainerSoftDel{}, r); len(f) != 0 {
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

func TestAZURE202(t *testing.T) {
	id := "AEGIS-AZURE-202"
	mustFinding(t, runRule(kvCertNoAutoRenew{}, res("azurerm_key_vault_certificate", "c", map[string]ir.Value{
		"certificate_policy": blks(3, blk()),
	})), id)
	r := res("azurerm_key_vault_certificate", "c", map[string]ir.Value{
		"certificate_policy": blks(3, blk("lifetime_action", blks(4, blk("action", ks("EmailContacts", 5))))),
	})
	if f := runRule(kvCertNoAutoRenew{}, r); len(f) != 0 {
		t.Fatalf("lifetime_action present must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-203: Storage blob without versioning
// ---------------------------------------------------------------------------

func TestAZURE203(t *testing.T) {
	id := "AEGIS-AZURE-203"
	mustFinding(t, runRule(storageBlobNoVersioning{}, res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk()),
	})), id)
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk("versioning_enabled", kv(true, 4))),
	})
	if f := runRule(storageBlobNoVersioning{}, r); len(f) != 0 {
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
