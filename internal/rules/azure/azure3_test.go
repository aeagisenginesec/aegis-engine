package azure

import (
	"testing"

	"aegis/internal/ir"
)

// TestAZURE026_NoHTTPSOnlyFires verifies HTTP traffic detection.
func TestAZURE026_NoHTTPSOnlyFires(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{"https_traffic_only_enabled": kv(false, 3)})
	mustFinding(t, runRule(storageNoHTTPSOnly{}, r), "AEGIS-AZURE-026")
}

func TestAZURE026_HTTPSQuiet(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{"https_traffic_only_enabled": kv(true, 3)})
	if len(runRule(storageNoHTTPSOnly{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE027_WeakTLSFires verifies weak TLS detection.
func TestAZURE027_WeakTLSFires(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{"min_tls_version": ks("TLS1_0", 3)})
	mustFinding(t, runRule(storageWeakTLS{}, r), "AEGIS-AZURE-027")
}

func TestAZURE027_TLS12Quiet(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{"min_tls_version": ks("TLS1_2", 3)})
	if len(runRule(storageWeakTLS{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE028_NoVersioningFires verifies blob versioning detection.
func TestAZURE028_NoVersioningFires(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk("versioning_enabled", kv(false, 4))),
	})
	mustFinding(t, runRule(storageNoBlobVersioning{}, r), "AEGIS-AZURE-028")
}

func TestAZURE028_VersioningQuiet(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{
		"blob_properties": blks(3, blk("versioning_enabled", kv(true, 4))),
	})
	if len(runRule(storageNoBlobVersioning{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE031_SharedKeyFires verifies shared key access detection.
func TestAZURE031_SharedKeyFires(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{"shared_access_key_enabled": kv(true, 3)})
	mustFinding(t, runRule(storageSharedKeyAccess{}, r), "AEGIS-AZURE-031")
}

func TestAZURE031_NoSharedKeyQuiet(t *testing.T) {
	r := res("azurerm_storage_account", "s", map[string]ir.Value{"shared_access_key_enabled": kv(false, 3)})
	if len(runRule(storageSharedKeyAccess{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE036_NoPurgeProtectionFires verifies Key Vault purge protection.
func TestAZURE036_NoPurgeProtectionFires(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"purge_protection_enabled": kv(false, 3)})
	mustFinding(t, runRule(keyVaultNoPurgeProtection{}, r), "AEGIS-AZURE-036")
}

func TestAZURE036_PurgeQuiet(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"purge_protection_enabled": kv(true, 3)})
	if len(runRule(keyVaultNoPurgeProtection{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE038_NoRBACFires verifies RBAC detection.
func TestAZURE038_NoRBACFires(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"enable_rbac_authorization": kv(false, 3)})
	mustFinding(t, runRule(keyVaultNoRBAC{}, r), "AEGIS-AZURE-038")
}

func TestAZURE038_RBACQuiet(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"enable_rbac_authorization": kv(true, 3)})
	if len(runRule(keyVaultNoRBAC{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE039_PublicAccessFires verifies Key Vault public access.
func TestAZURE039_PublicAccessFires(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"public_network_access_enabled": kv(true, 3)})
	mustFinding(t, runRule(keyVaultPublicAccess{}, r), "AEGIS-AZURE-039")
}

// TestAZURE040_SecretNoExpiryFires verifies secret expiration.
func TestAZURE040_SecretNoExpiryFires(t *testing.T) {
	r := res("azurerm_key_vault_secret", "s", map[string]ir.Value{})
	mustFinding(t, runRule(keyVaultSecretNoExpiry{}, r), "AEGIS-AZURE-040")
}

func TestAZURE040_SecretExpiryQuiet(t *testing.T) {
	r := res("azurerm_key_vault_secret", "s", map[string]ir.Value{"expiration_date": ks("2030-01-01T00:00:00Z", 3)})
	if len(runRule(keyVaultSecretNoExpiry{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE041_KeyNoRotationFires verifies key rotation policy.
func TestAZURE041_KeyNoRotationFires(t *testing.T) {
	r := res("azurerm_key_vault_key", "k", map[string]ir.Value{})
	mustFinding(t, runRule(keyVaultKeyNoRotation{}, r), "AEGIS-AZURE-041")
}

// TestAZURE043_SkuNotPremiumFires verifies premium SKU.
func TestAZURE043_SkuNotPremiumFires(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"sku_name": ks("standard", 3)})
	mustFinding(t, runRule(keyVaultSkuNotPremium{}, r), "AEGIS-AZURE-043")
}

func TestAZURE043_PremiumQuiet(t *testing.T) {
	r := res("azurerm_key_vault", "v", map[string]ir.Value{"sku_name": ks("premium", 3)})
	if len(runRule(keyVaultSkuNotPremium{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
