package arm

// Twin tests for the Sprint 3 storage translation fixes. Before these
// fixes, top-level blobServices/queueServices children were
// longest-prefix-mapped onto azurerm_storage_account itself (the fold
// keyed on types the prefix mapper never produced), so a hardened
// account drew a page of absence findings on a phantom second
// "account" named "<acct>/default", the real account never received
// its blob/queue properties, sasPolicy and Key Vault CMK were
// unreadable by the block-based rules, literal resourceId() calls
// degraded to Unknown (breaking private-endpoint linkage), and
// dhcpOptions DNS was invisible to AZURE-058.

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

const armStorageWithServices = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "foldacct",
      "location": "westeurope",
      "sku": { "name": "Standard_LRS" },
      "kind": "StorageV2",
      "properties": {
        "allowBlobPublicAccess": false,
        "defaultToOAuthAuthentication": true,
        "sasPolicy": {
          "sasExpirationPeriod": "1.00:00:00",
          "expirationAction": "Block"
        },
        "encryption": {
          "keySource": "Microsoft.Keyvault",
          "keyVaultProperties": {
            "keyVaultUri": "https://fold-vault.vault.azure.net/",
            "keyName": "cmk",
            "keyVersion": "abc123"
          }
        }
      }
    },
    {
      "type": "Microsoft.Storage/storageAccounts/blobServices",
      "apiVersion": "2023-01-01",
      "name": "foldacct/default",
      "properties": {
        "isVersioningEnabled": true,
        "deleteRetentionPolicy": { "enabled": true, "days": 7 },
        "containerDeleteRetentionPolicy": { "enabled": true, "days": 7 },
        "changeFeed": { "enabled": true }
      }
    },
    {
      "type": "Microsoft.Storage/storageAccounts/queueServices",
      "apiVersion": "2023-01-01",
      "name": "foldacct/default",
      "properties": {
        "analyticsLogging": { "delete": true, "read": true, "write": true, "version": "1.0" }
      }
    },
    {
      "type": "Microsoft.Network/virtualNetworks",
      "apiVersion": "2023-05-01",
      "name": "foldvnet",
      "location": "westeurope",
      "properties": {
        "dhcpOptions": { "dnsServers": ["10.0.0.4"] }
      }
    },
    {
      "type": "Microsoft.Network/privateEndpoints",
      "apiVersion": "2023-05-01",
      "name": "foldacct-pe",
      "location": "westeurope",
      "properties": {
        "privateLinkServiceConnections": [
          {
            "name": "blob",
            "properties": {
              "privateLinkServiceId": "[resourceId('Microsoft.Storage/storageAccounts', 'foldacct')]",
              "groupIds": ["blob"]
            }
          }
        ]
      }
    }
  ]
}`

func blocksOf(t *testing.T, r *ir.Resource, attr string) []map[string]ir.Value {
	t.Helper()
	v, ok := r.Attributes[attr]
	if !ok {
		t.Fatalf("attribute %s missing on %s", attr, r.Address())
	}
	blks, ok := v.Raw.([]ir.Value)
	if !ok || len(blks) == 0 {
		t.Fatalf("attribute %s is not a block list: %#v", attr, v.Raw)
	}
	out := make([]map[string]ir.Value, 0, len(blks))
	for _, b := range blks {
		m, ok := b.Raw.(map[string]ir.Value)
		if !ok {
			t.Fatalf("block %s element is not an object: %#v", attr, b.Raw)
		}
		out = append(out, m)
	}
	return out
}

func TestFoldStorageServicesIntoAccount(t *testing.T) {
	res := parseARM(t, armStorageWithServices)

	// The two service children fold away: account + vnet + PE remain,
	// and no phantom "<acct>/default" storage account exists.
	if len(res) != 3 {
		t.Fatalf("got %d resources, want 3 (account, vnet, private endpoint)", len(res))
	}
	for _, r := range res {
		if strings.Contains(r.Name, "/") {
			t.Errorf("unfolded child resource survived: %s", r.Address())
		}
	}
	acct := findResource(res, "azurerm_storage_account")
	if acct == nil {
		t.Fatal("no azurerm_storage_account")
	}

	blob := blocksOf(t, acct, "blob_properties")[0]
	if v, ok := blob["versioning_enabled"]; !ok || !mustBoolVal(v) {
		t.Errorf("blob_properties.versioning_enabled not folded true: %v", blob)
	}
	if _, ok := blob["delete_retention_policy"]; !ok {
		t.Errorf("blob_properties.delete_retention_policy not folded: %v", blob)
	}
	if _, ok := blob["container_delete_retention_policy"]; !ok {
		t.Errorf("blob_properties.container_delete_retention_policy not folded: %v", blob)
	}
	if v, ok := blob["change_feed_enabled"]; !ok || !mustBoolVal(v) {
		t.Errorf("blob_properties.change_feed_enabled not folded from changeFeed.enabled: %v", blob)
	}

	queue := blocksOf(t, acct, "queue_properties")[0]
	logBlks, ok := queue["logging"].Raw.([]ir.Value)
	if !ok || len(logBlks) == 0 {
		t.Fatalf("queue_properties.logging not folded: %v", queue)
	}
	logMap, _ := logBlks[0].Raw.(map[string]ir.Value)
	if v, ok := logMap["read"]; !ok || !mustBoolVal(v) {
		t.Errorf("queue_properties.logging.read not folded true: %v", logMap)
	}
}

func mustBoolVal(v ir.Value) bool {
	b, ok := v.AsBool()
	return ok && b
}

func TestTranslateStorageBlocks(t *testing.T) {
	res := parseARM(t, armStorageWithServices)
	acct := findResource(res, "azurerm_storage_account")
	if acct == nil {
		t.Fatal("no azurerm_storage_account")
	}
	sas := blocksOf(t, acct, "sas_policy")[0]
	if v, ok := sas["expiration_period"]; !ok {
		t.Errorf("sas_policy.expiration_period missing (sasExpirationPeriod not renamed): %v", sas)
	} else if s, _ := v.AsString(); s != "1.00:00:00" {
		t.Errorf("sas_policy.expiration_period = %q, want 1.00:00:00", s)
	}
	if v, ok := sas["expiration_action"]; !ok {
		t.Errorf("sas_policy.expiration_action missing: %v", sas)
	} else if s, _ := v.AsString(); s != "Block" {
		t.Errorf("sas_policy.expiration_action = %q, want Block", s)
	}
	cmk := blocksOf(t, acct, "customer_managed_key")[0]
	v, ok := cmk["key_vault_key_id"]
	if !ok {
		t.Fatalf("customer_managed_key.key_vault_key_id missing: %v", cmk)
	}
	if s, _ := v.AsString(); s != "https://fold-vault.vault.azure.net/keys/cmk/abc123" {
		t.Errorf("key_vault_key_id = %q, want versioned key URL", s)
	}
	// The OAuth rename: generic snake() would have produced
	// default_to_o_auth_authentication, invisible to AZURE-192.
	if !mustBool(t, acct, "default_to_oauth_authentication") {
		t.Errorf("default_to_oauth_authentication should be true after rename")
	}
}

func TestResourceIDLiteralBecomesRef(t *testing.T) {
	res := parseARM(t, armStorageWithServices)
	pe := findResource(res, "azurerm_private_endpoint")
	if pe == nil {
		t.Fatal("no azurerm_private_endpoint")
	}
	conns := blocksOf(t, pe, "private_link_service_connections")
	props, _ := conns[0]["properties"].Raw.(map[string]ir.Value)
	idv, ok := props["private_link_service_id"]
	if !ok {
		t.Fatalf("private_link_service_id missing: %v", conns[0])
	}
	if !idv.IsRef() {
		t.Fatalf("private_link_service_id should be a reference, got %#v", idv)
	}
	if idv.Ref != "azurerm_storage_account.foldacct.id" {
		t.Errorf("ref = %q, want azurerm_storage_account.foldacct.id", idv.Ref)
	}
}

func TestVNetDNSTranslation(t *testing.T) {
	res := parseARM(t, armStorageWithServices)
	vnet := findResource(res, "azurerm_virtual_network")
	if vnet == nil {
		t.Fatal("no azurerm_virtual_network")
	}
	v, ok := vnet.Attributes["dns_servers"]
	if !ok {
		t.Fatal("dns_servers not flattened from dhcpOptions")
	}
	servers, ok := v.Raw.([]ir.Value)
	if !ok || len(servers) != 1 {
		t.Fatalf("dns_servers = %#v, want one-element list", v.Raw)
	}
	if s, _ := servers[0].AsString(); s != "10.0.0.4" {
		t.Errorf("dns_servers[0] = %q, want 10.0.0.4", s)
	}
}

// Two accounts with a service child each, children interleaved
// between the parents: the fold must not mis-fold or panic (it
// previously indexed the output slice with input-slice positions).
func TestFoldInterleavedAccounts(t *testing.T) {
	const tmpl = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    { "type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
      "name": "accone", "location": "westeurope",
      "sku": { "name": "Standard_LRS" }, "kind": "StorageV2", "properties": {} },
    { "type": "Microsoft.Storage/storageAccounts/blobServices", "apiVersion": "2023-01-01",
      "name": "accone/default", "properties": { "isVersioningEnabled": true } },
    { "type": "Microsoft.Storage/storageAccounts", "apiVersion": "2023-01-01",
      "name": "acctwo", "location": "westeurope",
      "sku": { "name": "Standard_LRS" }, "kind": "StorageV2", "properties": {} },
    { "type": "Microsoft.Storage/storageAccounts/blobServices", "apiVersion": "2023-01-01",
      "name": "acctwo/default", "properties": { "isVersioningEnabled": false } }
  ]
}`
	res := parseARM(t, tmpl)
	if len(res) != 2 {
		t.Fatalf("got %d resources, want 2 accounts", len(res))
	}
	one := findResource(res, "azurerm_storage_account")
	_ = one
	seen := map[string]bool{}
	for _, r := range res {
		blob := blocksOf(t, &r, "blob_properties")[0]
		v := blob["versioning_enabled"]
		b, _ := v.AsBool()
		seen[r.Name] = b
	}
	if !seen["accone"] || seen["acctwo"] {
		t.Errorf("folded versioning flags crossed accounts: %v", seen)
	}
}
