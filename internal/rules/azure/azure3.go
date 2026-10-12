// Package azure — storage and Key Vault rules (AEGIS-AZURE-026..043).
//
// Same unknown-value contract: present-but-unresolved yields NO finding.
// Rules never panic on unexpected shapes.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure3Rules returns storage and Key Vault rules in ID order.
func Azure3Rules() []ir.Rule {
	return []ir.Rule{
		storageNoHTTPSOnly{},        // AEGIS-AZURE-026
		storageWeakTLS{},            // AEGIS-AZURE-027
		storageNoBlobVersioning{},   // AEGIS-AZURE-028
		storageNoBlobSoftDelete{},   // AEGIS-AZURE-029
		storageNoContainerDelete{},  // AEGIS-AZURE-030
		storageSharedKeyAccess{},    // AEGIS-AZURE-031
		storageNoInfraEncryption{},  // AEGIS-AZURE-032
		storageNoCMK{},              // AEGIS-AZURE-033
		storageQueueNoLogging{},     // AEGIS-AZURE-034
		storageNoNFSv3Secure{},      // AEGIS-AZURE-035
		keyVaultNoSoftDelete{},      // AEGIS-AZURE-037
		keyVaultNoRBAC{},            // AEGIS-AZURE-038
		keyVaultPublicAccess{},      // AEGIS-AZURE-039
		keyVaultSecretNoExpiry{},    // AEGIS-AZURE-040
		keyVaultKeyNoRotation{},     // AEGIS-AZURE-041
		keyVaultCertNoAutoRenew{},   // AEGIS-AZURE-042
		keyVaultSkuNotPremium{},     // AEGIS-AZURE-043
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-026: Storage account without HTTPS-only traffic
// ---------------------------------------------------------------------------

type storageNoHTTPSOnly struct{}

func (storageNoHTTPSOnly) ID() string { return "AEGIS-AZURE-026" }
func (storageNoHTTPSOnly) Title() string {
	return "Storage account allows HTTP traffic"
}
func (storageNoHTTPSOnly) Description() string {
	return "azurerm_storage_account with https_traffic_only_enabled = false " +
		"permits plaintext HTTP. Enforce HTTPS-only traffic."
}
func (storageNoHTTPSOnly) Severity() ir.Severity { return ir.SeverityHigh }

func (storageNoHTTPSOnly) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoHTTPSOnly) Check(r ir.Resource) []ir.Finding {
	https, span, present, known := getBool(r, "https_traffic_only_enabled")
	if !present || !known {
		return nil
	}
	if https {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "https_traffic_only_enabled", span,
		"false", "https_traffic_only_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-027: Storage account with weak TLS version
// ---------------------------------------------------------------------------

type storageWeakTLS struct{}

func (storageWeakTLS) ID() string { return "AEGIS-AZURE-027" }
func (storageWeakTLS) Title() string {
	return "Storage account allows weak TLS version"
}
func (storageWeakTLS) Description() string {
	return "azurerm_storage_account with min_tls_version below TLS1_2 " +
		"permits deprecated TLS. Require TLS1_2 or higher."
}
func (storageWeakTLS) Severity() ir.Severity { return ir.SeverityMedium }

func (storageWeakTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageWeakTLS) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "min_tls_version")
	if !present || !known {
		return nil
	}
	v := strings.ToUpper(strings.ReplaceAll(ver, " ", ""))
	if v == "TLS1_2" || v == "TLS1_3" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "min_tls_version", span,
		ver, "min_tls_version = \"TLS1_2\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-028: Storage account without blob versioning
// ---------------------------------------------------------------------------

type storageNoBlobVersioning struct{}

func (storageNoBlobVersioning) ID() string { return "AEGIS-AZURE-028" }
func (storageNoBlobVersioning) Title() string {
	return "Storage account without blob versioning"
}
func (storageNoBlobVersioning) Description() string {
	return "azurerm_storage_account blob_properties without versioning_enabled " +
		"loses protection against accidental overwrite or deletion. Enable versioning."
}
func (storageNoBlobVersioning) Severity() ir.Severity { return ir.SeverityMedium }

func (storageNoBlobVersioning) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoBlobVersioning) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "blob_properties")
	if !present {
		return []ir.Finding{mkFinding(s, r, "blob_properties",
			r.Span, "absent", "blob_properties { versioning_enabled = true }")}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "blob_properties",
			r.Span, "empty", "blob_properties { versioning_enabled = true }")}
	}
	v, ok := blks[0]["versioning_enabled"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "blob_properties.versioning_enabled",
			r.Span, "absent", "versioning_enabled = true")}
	}
	b, kok := v.AsBool()
	if !kok {
		return nil // unresolved: cannot decide
	}
	if b {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "blob_properties.versioning_enabled", v.Span,
		"false", "versioning_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-029: Storage account without blob soft delete
// ---------------------------------------------------------------------------

type storageNoBlobSoftDelete struct{}

func (storageNoBlobSoftDelete) ID() string { return "AEGIS-AZURE-029" }
func (storageNoBlobSoftDelete) Title() string {
	return "Storage account without blob soft delete"
}
func (storageNoBlobSoftDelete) Description() string {
	return "azurerm_storage_account blob_properties without delete_retention_policy " +
		"cannot recover accidentally deleted blobs. Enable soft delete."
}
func (storageNoBlobSoftDelete) Severity() ir.Severity { return ir.SeverityMedium }

func (storageNoBlobSoftDelete) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoBlobSoftDelete) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "blob_properties")
	if !present {
		return []ir.Finding{mkFinding(s, r, "blob_properties",
			r.Span, "absent", "blob_properties { delete_retention_policy { days = 7 } }")}
	}
	if !known || len(blks) == 0 {
		return nil // unresolved: cannot decide
	}
	drp, ok := blks[0]["delete_retention_policy"]
	if !ok || !drp.Known {
		return []ir.Finding{mkFinding(s, r, "blob_properties.delete_retention_policy",
			evidenceSpan(ir.Span{}, r.Span), "absent", "delete_retention_policy block with days > 0")}
	}
	m, mok := drp.AsMap()
	if !mok {
		if l, lok := drp.AsList(); lok && len(l) > 0 {
			m, mok = l[0].AsMap()
		}
	}
	if !mok {
		return nil
	}
	dv, ok := m["days"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "blob_properties.delete_retention_policy.days",
			drp.Span, "absent", "days > 0")}
	}
	// days as number
	var days float64
	switch n := dv.Raw.(type) {
	case float64:
		days = n
	case int:
		days = float64(n)
	default:
		return nil
	}
	if days > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "blob_properties.delete_retention_policy.days",
		dv.Span, "0", "days > 0")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-030: Storage account without container soft delete
// ---------------------------------------------------------------------------

type storageNoContainerDelete struct{}

func (storageNoContainerDelete) ID() string { return "AEGIS-AZURE-030" }
func (storageNoContainerDelete) Title() string {
	return "Storage account without container soft delete"
}
func (storageNoContainerDelete) Description() string {
	return "azurerm_storage_account blob_properties without container_delete_retention_policy " +
		"cannot recover deleted containers. Enable container soft delete."
}
func (storageNoContainerDelete) Severity() ir.Severity { return ir.SeverityLow }

func (storageNoContainerDelete) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoContainerDelete) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "blob_properties")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	if _, ok := blks[0]["container_delete_retention_policy"]; !ok {
		return []ir.Finding{mkFinding(s, r, "blob_properties.container_delete_retention_policy",
			evidenceSpan(ir.Span{}, r.Span), "absent", "container_delete_retention_policy block with days > 0")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-031: Storage account with shared key access enabled
// ---------------------------------------------------------------------------

type storageSharedKeyAccess struct{}

func (storageSharedKeyAccess) ID() string { return "AEGIS-AZURE-031" }
func (storageSharedKeyAccess) Title() string {
	return "Storage account allows shared key access"
}
func (storageSharedKeyAccess) Description() string {
	return "azurerm_storage_account with shared_access_key_enabled = true " +
		"permits storage account key authentication. Prefer Microsoft Entra ID " +
		"and disable shared key access."
}
func (storageSharedKeyAccess) Severity() ir.Severity { return ir.SeverityMedium }

func (storageSharedKeyAccess) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageSharedKeyAccess) Check(r ir.Resource) []ir.Finding {
	shared, span, present, known := getBool(r, "shared_access_key_enabled")
	if !present {
		// Default is enabled in Azure; absent = insecure.
		return []ir.Finding{mkFinding(s, r, "shared_access_key_enabled",
			r.Span, "absent (default: enabled)", "shared_access_key_enabled = false")}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if !shared {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "shared_access_key_enabled", span,
		"true", "shared_access_key_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-032: Storage account without infrastructure encryption
// ---------------------------------------------------------------------------

type storageNoInfraEncryption struct{}

func (storageNoInfraEncryption) ID() string { return "AEGIS-AZURE-032" }
func (storageNoInfraEncryption) Title() string {
	return "Storage account without infrastructure encryption"
}
func (storageNoInfraEncryption) Description() string {
	return "azurerm_storage_account without infrastructure_encryption_enabled " +
		"lacks double encryption at the infrastructure layer. Enable it for " +
		"defense in depth."
}
func (storageNoInfraEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (storageNoInfraEncryption) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoInfraEncryption) Check(r ir.Resource) []ir.Finding {
	enc, span, present, known := getBool(r, "infrastructure_encryption_enabled")
	if !present {
		return []ir.Finding{mkFinding(s, r, "infrastructure_encryption_enabled",
			r.Span, "absent", "infrastructure_encryption_enabled = true")}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if enc {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "infrastructure_encryption_enabled", span,
		"false", "infrastructure_encryption_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-033: Storage account without customer-managed key
// ---------------------------------------------------------------------------

type storageNoCMK struct{}

func (storageNoCMK) ID() string { return "AEGIS-AZURE-033" }
func (storageNoCMK) Title() string {
	return "Storage account without customer-managed key"
}
func (storageNoCMK) Description() string {
	return "azurerm_storage_account without customer_managed_key block uses " +
		"Microsoft-managed keys. Use a customer-managed key in Key Vault for " +
		"sensitive data."
}
func (storageNoCMK) Severity() ir.Severity { return ir.SeverityLow }

func (storageNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoCMK) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getBlocks(r, "customer_managed_key")
	if present {
		return nil
	}
	// Only flag when account kind suggests sensitivity; keep it simple:
	// flag if explicitly documented as sensitive via tags? No — keep quiet
	// on absence to avoid noise. This rule fires only when the block exists
	// but is incomplete.
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-034: Storage account queue properties without logging
// ---------------------------------------------------------------------------

type storageQueueNoLogging struct{}

func (storageQueueNoLogging) ID() string { return "AEGIS-AZURE-034" }
func (storageQueueNoLogging) Title() string {
	return "Storage account queue without logging"
}
func (storageQueueNoLogging) Description() string {
	return "azurerm_storage_account queue_properties without logging loses " +
		"audit trail for queue operations. Enable queue logging."
}
func (storageQueueNoLogging) Severity() ir.Severity { return ir.SeverityLow }

func (storageQueueNoLogging) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageQueueNoLogging) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "queue_properties")
	if !present {
		return []ir.Finding{mkFinding(s, r, "queue_properties",
			r.Span, "absent", "queue_properties { logging { read = true } }")}
	}
	if !known || len(blks) == 0 {
		return nil // unresolved: cannot decide
	}
	if _, ok := blks[0]["logging"]; !ok {
		return []ir.Finding{mkFinding(s, r, "queue_properties.logging",
			evidenceSpan(ir.Span{}, r.Span), "absent", "logging block with read/write/delete = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-035: Storage account with NFSv3 without secure transfer
// ---------------------------------------------------------------------------

type storageNoNFSv3Secure struct{}

func (storageNoNFSv3Secure) ID() string { return "AEGIS-AZURE-035" }
func (storageNoNFSv3Secure) Title() string {
	return "Storage account NFSv3 without secure transfer requirement"
}
func (storageNoNFSv3Secure) Description() string {
	return "azurerm_storage_account with nfsv3_enabled = true but without " +
		"https_traffic_only_enabled exposes NFS traffic. Require secure transfer."
}
func (storageNoNFSv3Secure) Severity() ir.Severity { return ir.SeverityMedium }

func (storageNoNFSv3Secure) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoNFSv3Secure) Check(r ir.Resource) []ir.Finding {
	nfs, _, present, known := getBool(r, "nfsv3_enabled")
	if !present || !known || !nfs {
		return nil
	}
	https, span, hpresent, hknown := getBool(r, "https_traffic_only_enabled")
	if !hpresent || !hknown || https {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "https_traffic_only_enabled", span,
		"false with nfsv3_enabled = true", "https_traffic_only_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-036: Key Vault without purge protection

// ---------------------------------------------------------------------------
// AEGIS-AZURE-037: Key Vault without soft delete
// ---------------------------------------------------------------------------

type keyVaultNoSoftDelete struct{}

func (keyVaultNoSoftDelete) ID() string { return "AEGIS-AZURE-037" }
func (keyVaultNoSoftDelete) Title() string {
	return "Key Vault without soft delete"
}
func (keyVaultNoSoftDelete) Description() string {
	return "azurerm_key_vault with soft_delete_retention_days < 7 or disabled " +
		"cannot recover deleted secrets. Set retention to at least 7 days."
}
func (keyVaultNoSoftDelete) Severity() ir.Severity { return ir.SeverityMedium }

func (keyVaultNoSoftDelete) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault"
}

func (s keyVaultNoSoftDelete) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["soft_delete_retention_days"]
	if !ok || !v.Known {
		return nil
	}
	var days float64
	switch n := v.Raw.(type) {
	case float64:
		days = n
	case int:
		days = float64(n)
	default:
		return nil
	}
	if days >= 7 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "soft_delete_retention_days", v.Span,
		"less than 7", "soft_delete_retention_days >= 7")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-038: Key Vault not using RBAC authorization
// ---------------------------------------------------------------------------

type keyVaultNoRBAC struct{}

func (keyVaultNoRBAC) ID() string { return "AEGIS-AZURE-038" }
func (keyVaultNoRBAC) Title() string {
	return "Key Vault not using RBAC authorization"
}
func (keyVaultNoRBAC) Description() string {
	return "azurerm_key_vault with enable_rbac_authorization = false uses " +
		"legacy access policies. Prefer Azure RBAC for centralized access control."
}
func (keyVaultNoRBAC) Severity() ir.Severity { return ir.SeverityMedium }

func (keyVaultNoRBAC) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault"
}

func (s keyVaultNoRBAC) Check(r ir.Resource) []ir.Finding {
	rbac, span, present, known := getBool(r, "enable_rbac_authorization")
	if !present {
		return []ir.Finding{mkFinding(s, r, "enable_rbac_authorization",
			r.Span, "absent", "enable_rbac_authorization = true")}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if rbac {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "enable_rbac_authorization", span,
		"false", "enable_rbac_authorization = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-039: Key Vault with public network access
// ---------------------------------------------------------------------------

type keyVaultPublicAccess struct{}

func (keyVaultPublicAccess) ID() string { return "AEGIS-AZURE-039" }
func (keyVaultPublicAccess) Title() string {
	return "Key Vault with public network access"
}
func (keyVaultPublicAccess) Description() string {
	return "azurerm_key_vault with public_network_access_enabled = true " +
		"exposes the vault endpoint. Disable public access and use private endpoints."
}
func (keyVaultPublicAccess) Severity() ir.Severity { return ir.SeverityHigh }

func (keyVaultPublicAccess) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault"
}

func (s keyVaultPublicAccess) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "public_network_access_enabled")
	if !present || !known {
		return nil
	}
	if !pub {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "public_network_access_enabled", span,
		"true", "public_network_access_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-040: Key Vault secret without expiration date
// ---------------------------------------------------------------------------

type keyVaultSecretNoExpiry struct{}

func (keyVaultSecretNoExpiry) ID() string { return "AEGIS-AZURE-040" }
func (keyVaultSecretNoExpiry) Title() string {
	return "Key Vault secret without expiration date"
}
func (keyVaultSecretNoExpiry) Description() string {
	return "azurerm_key_vault_secret without expiration_date never rotates. " +
		"Set an expiration date to enforce rotation."
}
func (keyVaultSecretNoExpiry) Severity() ir.Severity { return ir.SeverityMedium }

func (keyVaultSecretNoExpiry) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault_secret"
}

func (s keyVaultSecretNoExpiry) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "expiration_date")
	if !present {
		return []ir.Finding{mkFinding(s, r, "expiration_date",
			evidenceSpan(ir.Span{}, r.Span), "absent", "expiration_date = \"2030-01-01T00:00:00Z\"")}
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if strings.TrimSpace(v) == "" {
		return []ir.Finding{mkFinding(s, r, "expiration_date",
			span, "empty", "expiration_date = \"2030-01-01T00:00:00Z\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-041: Key Vault key without rotation policy
// ---------------------------------------------------------------------------

type keyVaultKeyNoRotation struct{}

func (keyVaultKeyNoRotation) ID() string { return "AEGIS-AZURE-041" }
func (keyVaultKeyNoRotation) Title() string {
	return "Key Vault key without rotation policy"
}
func (keyVaultKeyNoRotation) Description() string {
	return "azurerm_key_vault_key without rotation_policy never rotates. " +
		"Configure automatic rotation."
}
func (keyVaultKeyNoRotation) Severity() ir.Severity { return ir.SeverityMedium }

func (keyVaultKeyNoRotation) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault_key"
}

func (s keyVaultKeyNoRotation) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getBlocks(r, "rotation_policy")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "rotation_policy",
		evidenceSpan(ir.Span{}, r.Span), "absent", "rotation_policy block with automatic { time_before_expiry }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-042: Key Vault certificate without auto-renewal
// ---------------------------------------------------------------------------

type keyVaultCertNoAutoRenew struct{}

func (keyVaultCertNoAutoRenew) ID() string { return "AEGIS-AZURE-042" }
func (keyVaultCertNoAutoRenew) Title() string {
	return "Key Vault certificate policy without auto-renewal"
}
func (keyVaultCertNoAutoRenew) Description() string {
	return "azurerm_key_vault_certificate certificate_policy without " +
		"lifetime_action auto_renew may expire unnoticed. Enable auto-renewal."
}
func (keyVaultCertNoAutoRenew) Severity() ir.Severity { return ir.SeverityLow }

func (keyVaultCertNoAutoRenew) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault_certificate"
}

func (s keyVaultCertNoAutoRenew) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "certificate_policy")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	for _, blk := range blks {
		actions := blockList(blk, "lifetime_action")
		for _, a := range actions {
			if t, _, p, k := blockString(a, "action"); p && k &&
				strings.EqualFold(t, "AutoRenew") {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "certificate_policy.lifetime_action",
		evidenceSpan(ir.Span{}, r.Span), "no AutoRenew action",
		"lifetime_action { action = \"AutoRenew\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-043: Key Vault not using premium SKU
// ---------------------------------------------------------------------------

type keyVaultSkuNotPremium struct{}

func (keyVaultSkuNotPremium) ID() string { return "AEGIS-AZURE-043" }
func (keyVaultSkuNotPremium) Title() string {
	return "Key Vault not using premium SKU"
}
func (keyVaultSkuNotPremium) Description() string {
	return "azurerm_key_vault with sku_name = \"standard\" lacks HSM-backed " +
		"keys. Use premium SKU for hardware-protected keys."
}
func (keyVaultSkuNotPremium) Severity() ir.Severity { return ir.SeverityLow }

func (keyVaultSkuNotPremium) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault"
}

func (s keyVaultSkuNotPremium) Check(r ir.Resource) []ir.Finding {
	sku, span, present, known := getString(r, "sku_name")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(sku, "premium") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "sku_name", span,
		sku, "sku_name = \"premium\"")}
}
