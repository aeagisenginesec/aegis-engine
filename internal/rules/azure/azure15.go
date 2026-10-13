// Package azure — Key Vault & Storage hardening round (AEGIS-AZURE-186..205).
//
// Deepens Key Vault (network ACLs, RBAC authorization, HSM keys, secret
// expiry) and Storage (shared keys, OAuth default, cross-tenant
// replication, SAS policy, nested public access, infrastructure
// encryption, container access, CMK, network rules).
//
// Absent-attribute policy for this file: absent yields a finding when the
// provider default is insecure. Present-but-unresolved yields NO finding.
package azure

import (
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// Azure15Rules returns Key Vault & Storage hardening rules in ID order.
func Azure15Rules() []ir.Rule {
	return []ir.Rule{
		kvSoftDeleteRetention{},   // AEGIS-AZURE-186
		kvNetworkAclsOpen{},       // AEGIS-AZURE-187
		kvKeyNotHSM{},             // AEGIS-AZURE-189
		storageSharedKeyEnabled{}, // AEGIS-AZURE-191
		storageNoOAuthDefault{},   // AEGIS-AZURE-192
		storageSasNotBlocked{},    // AEGIS-AZURE-194
		storageNestedPublic{},     // AEGIS-AZURE-195
		storageContainerPublic{},  // AEGIS-AZURE-197
		storageNetRulesOpen{},     // AEGIS-AZURE-199
		kvKeyNearExpiry{},         // AEGIS-AZURE-200
		storageStaticWebsite{},    // AEGIS-AZURE-201
		storageSFTPEnabled{},      // AEGIS-AZURE-204
		kvNoFirewallRules{},       // AEGIS-AZURE-205
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-186: Key Vault soft-delete retention under 90 days
// ---------------------------------------------------------------------------

type kvSoftDeleteRetention struct{}

func (kvSoftDeleteRetention) ID() string { return "AEGIS-AZURE-186" }
func (kvSoftDeleteRetention) Title() string {
	return "Key Vault soft-delete retention under 90 days"
}
func (kvSoftDeleteRetention) Description() string {
	return "azurerm_key_vault with soft_delete_retention_days below 90 " +
		"shortens the recovery window for accidentally deleted vaults. " +
		"Keep the maximum 90-day retention."
}
func (kvSoftDeleteRetention) Severity() ir.Severity { return ir.SeverityLow }

func (kvSoftDeleteRetention) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault"
}

func (s kvSoftDeleteRetention) Check(r ir.Resource) []ir.Finding {
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
	case int64:
		days = float64(n)
	default:
		return nil // unexpected shape: cannot decide
	}
	if days >= 90 {
		return nil
	}
	actual := "0"
	if days != 0 {
		actual = strings.TrimRight(strings.TrimRight(
			strconv.FormatFloat(days, 'f', 1, 64), "0"), ".")
	}
	return []ir.Finding{mkFinding(s, r, "soft_delete_retention_days", v.Span,
		actual, "soft_delete_retention_days = 90")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-187: Key Vault network ACLs allow public traffic
// ---------------------------------------------------------------------------

type kvNetworkAclsOpen struct{}

func (kvNetworkAclsOpen) ID() string { return "AEGIS-AZURE-187" }
func (kvNetworkAclsOpen) Title() string {
	return "Key Vault network ACLs allow public traffic"
}
func (kvNetworkAclsOpen) Description() string {
	return "azurerm_key_vault without a network_acls block (default allow) " +
		"or with default_action other than \"Deny\" accepts secret/key " +
		"operations from any network. Set default_action = \"Deny\" with " +
		"explicit allowances."
}
func (kvNetworkAclsOpen) Severity() ir.Severity { return ir.SeverityHigh }

func (kvNetworkAclsOpen) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault"
}

func (s kvNetworkAclsOpen) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "network_acls")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "network_acls",
			evidenceSpan(span, r.Span), "absent (default: allow all)",
			"network_acls { default_action = \"Deny\" }")}
	}
	for _, b := range blks {
		act, _, p, k := blockString(b, "default_action")
		if p && !k {
			return nil
		}
		if !p || !strings.EqualFold(strings.TrimSpace(act), "Deny") {
			return []ir.Finding{mkFinding(s, r, "network_acls",
				evidenceSpan(span, r.Span), "default_action = \""+act+"\"",
				"network_acls { default_action = \"Deny\" }")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-188: Key Vault not using RBAC authorization

// ---------------------------------------------------------------------------
// AEGIS-AZURE-189: Key Vault key not HSM-backed
// ---------------------------------------------------------------------------

type kvKeyNotHSM struct{}

func (kvKeyNotHSM) ID() string { return "AEGIS-AZURE-189" }
func (kvKeyNotHSM) Title() string {
	return "Key Vault key not HSM-backed"
}
func (kvKeyNotHSM) Description() string {
	return "azurerm_key_vault_key with a software-protected key_type " +
		"(RSA, EC, oct) stores key material in software. For " +
		"high-assurance workloads use HSM-backed types (RSA-HSM, EC-HSM) " +
		"in a Managed HSM or premium vault."
}
func (kvKeyNotHSM) Severity() ir.Severity { return ir.SeverityLow }

func (kvKeyNotHSM) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault_key"
}

func (s kvKeyNotHSM) Check(r ir.Resource) []ir.Finding {
	kt, span, present, known := getString(r, "key_type")
	if !present || !known {
		return nil
	}
	up := strings.ToUpper(strings.TrimSpace(kt))
	if strings.HasSuffix(up, "-HSM") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "key_type", span,
		kt, "key_type = \"RSA-HSM\" (or EC-HSM)")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-190: Key Vault secret without expiration date

// ---------------------------------------------------------------------------
// AEGIS-AZURE-191: Storage account with shared key access enabled
// ---------------------------------------------------------------------------

type storageSharedKeyEnabled struct{}

func (storageSharedKeyEnabled) ID() string { return "AEGIS-AZURE-191" }
func (storageSharedKeyEnabled) Title() string {
	return "Storage account with shared key access enabled"
}
func (storageSharedKeyEnabled) Description() string {
	return "azurerm_storage_account with shared_access_key_enabled " +
		"(the provider default) permits Shared Key authorization, which " +
		"bypasses Entra ID and cannot be scoped. Disable it and use " +
		"Entra ID with default_to_oauth_authentication."
}
func (storageSharedKeyEnabled) Severity() ir.Severity { return ir.SeverityMedium }

func (storageSharedKeyEnabled) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageSharedKeyEnabled) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "shared_access_key_enabled")
	if present && !known {
		return nil
	}
	if present && !en {
		return nil
	}
	actual := "true"
	if !present {
		actual = "absent (provider default: enabled)"
	}
	return []ir.Finding{mkFinding(s, r, "shared_access_key_enabled",
		evidenceSpan(span, r.Span), actual,
		"shared_access_key_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-192: Storage account not defaulting to OAuth authentication
// ---------------------------------------------------------------------------

type storageNoOAuthDefault struct{}

func (storageNoOAuthDefault) ID() string { return "AEGIS-AZURE-192" }
func (storageNoOAuthDefault) Title() string {
	return "Storage account not defaulting to OAuth authentication"
}
func (storageNoOAuthDefault) Description() string {
	return "azurerm_storage_account without " +
		"default_to_oauth_authentication = true lets clients fall back " +
		"to Shared Key auth. Default to Entra ID OAuth for data-plane " +
		"operations."
}
func (storageNoOAuthDefault) Severity() ir.Severity { return ir.SeverityMedium }

func (storageNoOAuthDefault) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoOAuthDefault) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "default_to_oauth_authentication",
		"default_to_oauth_authentication = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-193: Storage account without blob soft delete

// blockDays extracts a numeric day count from a block map; -1 when absent
// or undecidable.
func blockDays(m map[string]ir.Value, name string) float64 {
	v, ok := m[name]
	if !ok || !v.Known {
		return -1
	}
	switch n := v.Raw.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	}
	return -1
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-194: Storage SAS policy not blocking on expiry
// ---------------------------------------------------------------------------

type storageSasNotBlocked struct{}

func (storageSasNotBlocked) ID() string { return "AEGIS-AZURE-194" }
func (storageSasNotBlocked) Title() string {
	return "Storage SAS policy not blocking expired tokens"
}
func (storageSasNotBlocked) Description() string {
	return "azurerm_storage_account sas_policy with expiration_action " +
		"other than \"Block\" only logs (or ignores) use of expired SAS " +
		"tokens. Set expiration_action = \"Block\" and keep " +
		"expiration_period short."
}
func (storageSasNotBlocked) Severity() ir.Severity { return ir.SeverityMedium }

func (storageSasNotBlocked) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageSasNotBlocked) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "sas_policy")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		act, _, p, k := blockString(b, "expiration_action")
		if p && !k {
			return nil
		}
		if !p || !strings.EqualFold(strings.TrimSpace(act), "Block") {
			actual := "absent (default: Log)"
			if p {
				actual = act
			}
			return []ir.Finding{mkFinding(s, r, "sas_policy",
				evidenceSpan(span, r.Span), actual,
				"sas_policy { expiration_action = \"Block\" }")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-195: Storage account allows nested public items
// ---------------------------------------------------------------------------

type storageNestedPublic struct{}

func (storageNestedPublic) ID() string { return "AEGIS-AZURE-195" }
func (storageNestedPublic) Title() string {
	return "Storage account allows nested public items"
}
func (storageNestedPublic) Description() string {
	return "azurerm_storage_account with allow_nested_items_to_be_public " +
		"(the provider default) lets containers and blobs be marked " +
		"public even when account-level public access is off. Disable it " +
		"to enforce private-by-default."
}
func (storageNestedPublic) Severity() ir.Severity { return ir.SeverityMedium }

func (storageNestedPublic) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNestedPublic) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "allow_nested_items_to_be_public")
	if present && !known {
		return nil
	}
	if present && !en {
		return nil
	}
	actual := "true"
	if !present {
		actual = "absent (provider default: enabled)"
	}
	return []ir.Finding{mkFinding(s, r, "allow_nested_items_to_be_public",
		evidenceSpan(span, r.Span), actual,
		"allow_nested_items_to_be_public = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-196: Storage account without infrastructure encryption

// ---------------------------------------------------------------------------
// AEGIS-AZURE-197: Storage container not private
// ---------------------------------------------------------------------------

type storageContainerPublic struct{}

func (storageContainerPublic) ID() string { return "AEGIS-AZURE-197" }
func (storageContainerPublic) Title() string {
	return "Storage container with public access"
}
func (storageContainerPublic) Description() string {
	return "azurerm_storage_container with container_access_type other " +
		"than \"private\" exposes blobs anonymously. Keep containers " +
		"private unless public content delivery is intended."
}
func (storageContainerPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (storageContainerPublic) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_container"
}

func (s storageContainerPublic) Check(r ir.Resource) []ir.Finding {
	at, span, present, known := getString(r, "container_access_type")
	if !present || !known {
		return nil // default private: secure
	}
	if strings.EqualFold(strings.TrimSpace(at), "private") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "container_access_type", span,
		at, "container_access_type = \"private\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-198: Storage account without container soft delete

// ---------------------------------------------------------------------------
// AEGIS-AZURE-199: Storage network rules allow public traffic
// ---------------------------------------------------------------------------

type storageNetRulesOpen struct{}

func (storageNetRulesOpen) ID() string { return "AEGIS-AZURE-199" }
func (storageNetRulesOpen) Title() string {
	return "Storage network rules allow public traffic"
}
func (storageNetRulesOpen) Description() string {
	return "azurerm_storage_account_network_rules with default_action " +
		"other than \"Deny\" accepts storage requests from any network. " +
		"Set default_action = \"Deny\" with explicit allowances."
}
func (storageNetRulesOpen) Severity() ir.Severity { return ir.SeverityHigh }

func (storageNetRulesOpen) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account_network_rules"
}

func (s storageNetRulesOpen) Check(r ir.Resource) []ir.Finding {
	act, span, present, known := getString(r, "default_action")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(act), "Deny") {
		return nil
	}
	// An empty value is not an explicit Deny: keep firing, but report
	// a non-empty Actual so the evidence is meaningful.
	actual := act
	if actual == "" {
		actual = "(empty — provider default is Allow)"
	}
	return []ir.Finding{mkFinding(s, r, "default_action", span,
		actual, "default_action = \"Deny\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-200: Key Vault key near expiry without rotation notice
// ---------------------------------------------------------------------------

type kvKeyNearExpiry struct{}

func (kvKeyNearExpiry) ID() string { return "AEGIS-AZURE-200" }
func (kvKeyNearExpiry) Title() string {
	return "Key Vault key without expiration date"
}
func (kvKeyNearExpiry) Description() string {
	return "azurerm_key_vault_key without expiration_date never rotates, " +
		"so a compromised key stays valid indefinitely. Set an " +
		"expiration date and automate rotation."
}
func (kvKeyNearExpiry) Severity() ir.Severity { return ir.SeverityMedium }

func (kvKeyNearExpiry) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault_key"
}

func (s kvKeyNearExpiry) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["expiration_date"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "expiration_date", r.Span,
			"absent (never expires)", "expiration_date = \"<rfc3339>\"")}
	}
	if !v.Known {
		return nil
	}
	sv, kok := v.AsString()
	if !kok || strings.TrimSpace(sv) == "" {
		return []ir.Finding{mkFinding(s, r, "expiration_date", v.Span,
			"empty", "expiration_date = \"<rfc3339>\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-201: Storage account with static website hosting
// ---------------------------------------------------------------------------

type storageStaticWebsite struct{}

func (storageStaticWebsite) ID() string { return "AEGIS-AZURE-201" }
func (storageStaticWebsite) Title() string {
	return "Storage account with static website hosting enabled"
}
func (storageStaticWebsite) Description() string {
	return "azurerm_storage_account with a static_website block serves " +
		"content over HTTP(S) directly from storage. Ensure static " +
		"website hosting is intended and front it with CDN/WAF rather " +
		"than exposing the storage endpoint."
}
func (storageStaticWebsite) Severity() ir.Severity { return ir.SeverityLow }

func (storageStaticWebsite) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageStaticWebsite) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "static_website")
	if !present || !known {
		return nil
	}
	if len(blks) == 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "static_website",
		evidenceSpan(span, r.Span), "static website hosting enabled",
		"remove static_website unless intended")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-202: Key Vault certificate without lifetime actions

// ---------------------------------------------------------------------------
// AEGIS-AZURE-203: Storage blob without versioning

// ---------------------------------------------------------------------------
// AEGIS-AZURE-204: Storage account with SFTP enabled
// ---------------------------------------------------------------------------

type storageSFTPEnabled struct{}

func (storageSFTPEnabled) ID() string { return "AEGIS-AZURE-204" }
func (storageSFTPEnabled) Title() string {
	return "Storage account with SFTP enabled"
}
func (storageSFTPEnabled) Description() string {
	return "azurerm_storage_account with sftp_enabled = true exposes an " +
		"SSH endpoint for blob storage. Ensure SFTP is required, local " +
		"users authenticate with SSH keys, and network rules restrict " +
		"source networks."
}
func (storageSFTPEnabled) Severity() ir.Severity { return ir.SeverityLow }

func (storageSFTPEnabled) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageSFTPEnabled) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "sftp_enabled")
	if !present || !known {
		return nil // default false: secure
	}
	if !en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "sftp_enabled", span,
		"true", "sftp_enabled = false (unless required)")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-205: Key Vault without firewall IP rules
// ---------------------------------------------------------------------------

type kvNoFirewallRules struct{}

func (kvNoFirewallRules) ID() string { return "AEGIS-AZURE-205" }
func (kvNoFirewallRules) Title() string {
	return "Key Vault firewall without IP rules"
}
func (kvNoFirewallRules) Description() string {
	return "azurerm_key_vault network_acls with default_action = \"Deny\" " +
		"but no ip_rules or virtual_network_subnet_ids leaves the vault " +
		"unreachable — or, when combined with bypass, silently wide open. " +
		"Define explicit IP or VNet allowances alongside the Deny default."
}
func (kvNoFirewallRules) Severity() ir.Severity { return ir.SeverityLow }

func (kvNoFirewallRules) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault"
}

func (s kvNoFirewallRules) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "network_acls")
	if !present || !known || len(blks) == 0 {
		return nil // covered by AEGIS-AZURE-187 when absent/open
	}
	for _, b := range blks {
		act, _, p, k := blockString(b, "default_action")
		if p && !k {
			return nil
		}
		if !p || !strings.EqualFold(strings.TrimSpace(act), "Deny") {
			return nil // not locked down; 187 handles it
		}
		ips, _, iok := getStringListFromMap(b, "ip_rules")
		subs, _, sok := getStringListFromMap(b, "virtual_network_subnet_ids")
		if (!iok || len(ips) == 0) && (!sok || len(subs) == 0) {
			return []ir.Finding{mkFinding(s, r, "network_acls",
				evidenceSpan(span, r.Span),
				"default_action = \"Deny\" with no allowances",
				"network_acls { ip_rules = [...] }")}
		}
	}
	return nil
}
