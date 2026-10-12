// Package azure — AKS cluster hardening rules, round 3 (AEGIS-AZURE-127..136).
//
// Absent-attribute policy for this file (documented per the pack contract):
// these "without X" hardening rules treat an absent attribute as a finding,
// because the azurerm provider defaults are the insecure ones (local admin
// accounts enabled, no Azure AD integration, no Key Vault secrets provider,
// no Defender, image cleaner off, no node OS auto-upgrade, no host
// encryption, cost analysis off, upgrade channel "none", OIDC issuer off).
// Present-but-unresolved values still yield NO finding.
//
// AEGIS-AZURE-135/136 are strict complements of AEGIS-AZURE-073/076: those
// fire only when the attribute is present with the insecure value; these fire
// when the attribute is absent (provider default = insecure). They never
// double-fire on the same resource.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure10Rules returns AKS hardening rules in ID order.
func Azure10Rules() []ir.Rule {
	return []ir.Rule{
		aksLocalAccountsEnabled{},   // AEGIS-AZURE-127
		aksNoAADIntegration{},       // AEGIS-AZURE-128
		aksNoKVSecretsProvider{},    // AEGIS-AZURE-129
		aksNoDefender{},             // AEGIS-AZURE-130
		aksNoImageCleaner{},         // AEGIS-AZURE-131
		aksNoNodeOSAutoUpgrade{},    // AEGIS-AZURE-132
		aksNoHostEncryption{},       // AEGIS-AZURE-133
		aksNoCostAnalysis{},         // AEGIS-AZURE-134
		aksNoUpgradeChannelStrict{}, // AEGIS-AZURE-135
		aksNoOIDCIssuerStrict{},     // AEGIS-AZURE-136
	}
}

func aksApplies(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-127: AKS cluster with local accounts enabled
// ---------------------------------------------------------------------------

type aksLocalAccountsEnabled struct{}

func (aksLocalAccountsEnabled) ID() string { return "AEGIS-AZURE-127" }
func (aksLocalAccountsEnabled) Title() string {
	return "AKS cluster with local admin accounts enabled"
}
func (aksLocalAccountsEnabled) Description() string {
	return "azurerm_kubernetes_cluster without local_account_disabled = true " +
		"keeps the built-in cluster-admin Kubernetes account active, " +
		"bypassing Azure AD authentication. Disable local accounts and " +
		"use Azure AD / Microsoft Entra ID RBAC."
}
func (aksLocalAccountsEnabled) Severity() ir.Severity { return ir.SeverityHigh }

func (aksLocalAccountsEnabled) AppliesTo(resType string) bool { return aksApplies(resType) }

func (s aksLocalAccountsEnabled) Check(r ir.Resource) []ir.Finding {
	disabled, span, present, known := getBool(r, "local_account_disabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && disabled {
		return nil
	}
	actual := "absent (default false)"
	if present {
		actual = "false"
	}
	return []ir.Finding{mkFinding(s, r, "local_account_disabled",
		evidenceSpan(span, r.Span), actual, "local_account_disabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-128: AKS cluster without Azure AD RBAC integration
// ---------------------------------------------------------------------------

type aksNoAADIntegration struct{}

func (aksNoAADIntegration) ID() string { return "AEGIS-AZURE-128" }
func (aksNoAADIntegration) Title() string {
	return "AKS cluster without Azure AD RBAC integration"
}
func (aksNoAADIntegration) Description() string {
	return "azurerm_kubernetes_cluster without an " +
		"azure_active_directory_role_based_access_control block cannot map " +
		"Kubernetes RBAC to Microsoft Entra ID identities, leaving cluster " +
		"access to local accounts. Enable Azure AD RBAC integration."
}
func (aksNoAADIntegration) Severity() ir.Severity { return ir.SeverityMedium }

func (aksNoAADIntegration) AppliesTo(resType string) bool { return aksApplies(resType) }

func (s aksNoAADIntegration) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "azure_active_directory_role_based_access_control")
	if !present {
		return []ir.Finding{mkFinding(s, r, "azure_active_directory_role_based_access_control",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"azure_active_directory_role_based_access_control { managed = true ... }")}
	}
	if !known || len(blks) == 0 {
		return nil // unresolved: cannot decide
	}
	managed, _, mpresent, mknown := blockBool(blks[0], "managed")
	if mpresent && !mknown {
		return nil
	}
	if !mpresent || !managed {
		return []ir.Finding{mkFinding(s, r,
			"azure_active_directory_role_based_access_control.managed",
			evidenceSpan(span, r.Span), "disabled or absent",
			"managed = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-129: AKS cluster without Key Vault secrets provider
// ---------------------------------------------------------------------------

type aksNoKVSecretsProvider struct{}

func (aksNoKVSecretsProvider) ID() string { return "AEGIS-AZURE-129" }
func (aksNoKVSecretsProvider) Title() string {
	return "AKS cluster without Key Vault secrets provider"
}
func (aksNoKVSecretsProvider) Description() string {
	return "azurerm_kubernetes_cluster without a key_vault_secrets_provider " +
		"block cannot mount secrets from Azure Key Vault as CSI volumes, " +
		"pushing workloads toward Kubernetes Secrets or environment " +
		"variables. Enable the Key Vault secrets provider addon."
}
func (aksNoKVSecretsProvider) Severity() ir.Severity { return ir.SeverityMedium }

func (aksNoKVSecretsProvider) AppliesTo(resType string) bool { return aksApplies(resType) }

func (s aksNoKVSecretsProvider) Check(r ir.Resource) []ir.Finding {
	if _, _, present, _ := getBlocks(r, "key_vault_secrets_provider"); present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "key_vault_secrets_provider",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"key_vault_secrets_provider { secret_rotation_enabled = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-130: AKS cluster without Microsoft Defender for Containers
// ---------------------------------------------------------------------------

type aksNoDefender struct{}

func (aksNoDefender) ID() string { return "AEGIS-AZURE-130" }
func (aksNoDefender) Title() string {
	return "AKS cluster without Microsoft Defender for Containers"
}
func (aksNoDefender) Description() string {
	return "azurerm_kubernetes_cluster without a microsoft_defender block " +
		"misses Defender for Containers threat detection on the cluster " +
		"and its images. Enable Microsoft Defender for Containers."
}
func (aksNoDefender) Severity() ir.Severity { return ir.SeverityMedium }

func (aksNoDefender) AppliesTo(resType string) bool { return aksApplies(resType) }

func (s aksNoDefender) Check(r ir.Resource) []ir.Finding {
	if _, _, present, _ := getBlocks(r, "microsoft_defender"); present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "microsoft_defender",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"microsoft_defender { log_analytics_workspace_id = ... }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-131: AKS cluster without image cleaner
// ---------------------------------------------------------------------------

type aksNoImageCleaner struct{}

func (aksNoImageCleaner) ID() string { return "AEGIS-AZURE-131" }
func (aksNoImageCleaner) Title() string {
	return "AKS cluster without image cleaner"
}
func (aksNoImageCleaner) Description() string {
	return "azurerm_kubernetes_cluster without image_cleaner_enabled = true " +
		"never evicts stale, potentially vulnerable container images from " +
		"node caches. Enable the AKS image cleaner."
}
func (aksNoImageCleaner) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoImageCleaner) AppliesTo(resType string) bool { return aksApplies(resType) }

func (s aksNoImageCleaner) Check(r ir.Resource) []ir.Finding {
	enabled, span, present, known := getBool(r, "image_cleaner_enabled")
	if present && !known {
		return nil
	}
	if present && enabled {
		return nil
	}
	actual := "absent (default false)"
	if present {
		actual = "false"
	}
	return []ir.Finding{mkFinding(s, r, "image_cleaner_enabled",
		evidenceSpan(span, r.Span), actual, "image_cleaner_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-132: AKS node pool without node OS auto-upgrade
// ---------------------------------------------------------------------------

type aksNoNodeOSAutoUpgrade struct{}

func (aksNoNodeOSAutoUpgrade) ID() string { return "AEGIS-AZURE-132" }
func (aksNoNodeOSAutoUpgrade) Title() string {
	return "AKS node pool without node OS auto-upgrade channel"
}
func (aksNoNodeOSAutoUpgrade) Description() string {
	return "azurerm_kubernetes_cluster default_node_pool without " +
		"node_os_upgrade_channel (SecurityPatch or NodeImage) leaves node " +
		"OS patching to manual upgrades, widening the window for kernel " +
		"vulnerabilities. Set node_os_upgrade_channel."
}
func (aksNoNodeOSAutoUpgrade) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoNodeOSAutoUpgrade) AppliesTo(resType string) bool { return aksApplies(resType) }

func (s aksNoNodeOSAutoUpgrade) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "default_node_pool")
	if !present || !known || len(blks) == 0 {
		return nil // no node pool block to judge: cannot decide
	}
	ch, _, cpresent, cknown := blockString(blks[0], "node_os_upgrade_channel")
	if cpresent && !cknown {
		return nil
	}
	if cpresent && !strings.EqualFold(strings.TrimSpace(ch), "none") {
		return nil
	}
	actual := "absent (default None)"
	if cpresent {
		actual = ch
	}
	return []ir.Finding{mkFinding(s, r, "default_node_pool.node_os_upgrade_channel",
		evidenceSpan(ir.Span{}, r.Span), actual,
		"node_os_upgrade_channel = \"SecurityPatch\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-133: AKS node pool without host encryption
// ---------------------------------------------------------------------------

type aksNoHostEncryption struct{}

func (aksNoHostEncryption) ID() string { return "AEGIS-AZURE-133" }
func (aksNoHostEncryption) Title() string {
	return "AKS node pool without host encryption"
}
func (aksNoHostEncryption) Description() string {
	return "azurerm_kubernetes_cluster default_node_pool without " +
		"host_encryption_enabled = true leaves node host disks (including " +
		"temporary disks) without host-level encryption. Enable host " +
		"encryption on the node pool."
}
func (aksNoHostEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (aksNoHostEncryption) AppliesTo(resType string) bool { return aksApplies(resType) }

func (s aksNoHostEncryption) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "default_node_pool")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	enc, _, epresent, eknown := blockBool(blks[0], "host_encryption_enabled")
	if epresent && !eknown {
		return nil
	}
	if epresent && enc {
		return nil
	}
	actual := "absent (default false)"
	if epresent {
		actual = "false"
	}
	return []ir.Finding{mkFinding(s, r, "default_node_pool.host_encryption_enabled",
		evidenceSpan(ir.Span{}, r.Span), actual,
		"host_encryption_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-134: AKS cluster without cost analysis
// ---------------------------------------------------------------------------

type aksNoCostAnalysis struct{}

func (aksNoCostAnalysis) ID() string { return "AEGIS-AZURE-134" }
func (aksNoCostAnalysis) Title() string {
	return "AKS cluster without cost analysis"
}
func (aksNoCostAnalysis) Description() string {
	return "Hygiene: azurerm_kubernetes_cluster without cost_analysis_enabled " +
		"= true has no cost visibility into cluster spend. Enable the cost " +
		"analysis addon."
}
func (aksNoCostAnalysis) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoCostAnalysis) AppliesTo(resType string) bool { return aksApplies(resType) }

func (s aksNoCostAnalysis) Check(r ir.Resource) []ir.Finding {
	enabled, span, present, known := getBool(r, "cost_analysis_enabled")
	if present && !known {
		return nil
	}
	if present && enabled {
		return nil
	}
	actual := "absent (default false)"
	if present {
		actual = "false"
	}
	return []ir.Finding{mkFinding(s, r, "cost_analysis_enabled",
		evidenceSpan(span, r.Span), actual, "cost_analysis_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-135: AKS cluster without automatic upgrade channel (strict)
// ---------------------------------------------------------------------------

type aksNoUpgradeChannelStrict struct{}

func (aksNoUpgradeChannelStrict) ID() string { return "AEGIS-AZURE-135" }
func (aksNoUpgradeChannelStrict) Title() string {
	return "AKS cluster without automatic upgrade channel"
}
func (aksNoUpgradeChannelStrict) Description() string {
	return "azurerm_kubernetes_cluster without automatic_upgrade_channel " +
		"defaults to no automatic upgrades, missing Kubernetes security " +
		"patches. Set an upgrade channel (patch, stable, rapid, node-image). " +
		"(Strict complement of AEGIS-AZURE-073, which covers an explicit " +
		"\"none\" value.)"
}
func (aksNoUpgradeChannelStrict) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoUpgradeChannelStrict) AppliesTo(resType string) bool { return aksApplies(resType) }

func (s aksNoUpgradeChannelStrict) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "automatic_upgrade_channel")
	if !present {
		return []ir.Finding{mkFinding(s, r, "automatic_upgrade_channel",
			evidenceSpan(ir.Span{}, r.Span), "absent (default none)",
			"automatic_upgrade_channel = \"patch\"")}
	}
	if !known {
		return nil
	}
	// Present-but-insecure ("none") is AEGIS-AZURE-073's finding; stay quiet
	// here so the two rules never double-fire.
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-136: AKS cluster without OIDC issuer (strict)
// ---------------------------------------------------------------------------

type aksNoOIDCIssuerStrict struct{}

func (aksNoOIDCIssuerStrict) ID() string { return "AEGIS-AZURE-136" }
func (aksNoOIDCIssuerStrict) Title() string {
	return "AKS cluster without OIDC issuer"
}
func (aksNoOIDCIssuerStrict) Description() string {
	return "azurerm_kubernetes_cluster without oidc_issuer_enabled defaults " +
		"the OIDC issuer to off, blocking workload identity federation for " +
		"pod-level Azure credentials. Enable the OIDC issuer. (Strict " +
		"complement of AEGIS-AZURE-076, which covers an explicit false value.)"
}
func (aksNoOIDCIssuerStrict) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoOIDCIssuerStrict) AppliesTo(resType string) bool { return aksApplies(resType) }

func (s aksNoOIDCIssuerStrict) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBool(r, "oidc_issuer_enabled")
	if !present {
		return []ir.Finding{mkFinding(s, r, "oidc_issuer_enabled",
			evidenceSpan(ir.Span{}, r.Span), "absent (default false)",
			"oidc_issuer_enabled = true")}
	}
	if !known {
		return nil
	}
	// Present (true or false) is AEGIS-AZURE-076's domain; stay quiet here so
	// the two rules never double-fire.
	return nil
}
