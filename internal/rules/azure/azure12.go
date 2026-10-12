// Package azure — storage account hardening rules, round 3 (AEGIS-AZURE-144..149).
//
// Gaps not covered by AEGIS-AZR-001/002, AEGIS-AZURE-006/021 or 119..126
// (public access, TLS, shared keys, SAS policy, soft delete, queue logging,
// private endpoints): infrastructure (double) encryption, cross-tenant
// replication, blob versioning, change feed, public network access (strict),
// and network rules (strict).
//
// Absent-attribute policy for this file: an absent attribute yields a
// finding when the provider default is the insecure one (no infrastructure
// encryption, cross-tenant replication allowed, no versioning/change feed,
// public network access on, no network rules). Present-but-unresolved values
// yield NO finding.
//
// AEGIS-AZURE-148/149 are strict complements of AEGIS-AZURE-006/021: those
// fire only when the insecure value is explicitly set; these fire when the
// attribute/block is absent (provider default = insecure). They never
// double-fire on the same resource.
package azure

import (
	"aegis/internal/ir"
)

// Azure12Rules returns storage hardening rules in ID order.
func Azure12Rules() []ir.Rule {
	return []ir.Rule{
		storageCrossTenantRepl{}, // AEGIS-AZURE-145
		storageNoChangeFeed{},    // AEGIS-AZURE-147
		storagePublicNetStrict{}, // AEGIS-AZURE-148
		storageNoNetworkRules{},  // AEGIS-AZURE-149
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-144: Storage account without infrastructure encryption

// ---------------------------------------------------------------------------
// AEGIS-AZURE-145: Storage account allows cross-tenant replication
// ---------------------------------------------------------------------------

type storageCrossTenantRepl struct{}

func (storageCrossTenantRepl) ID() string { return "AEGIS-AZURE-145" }
func (storageCrossTenantRepl) Title() string {
	return "Storage account allows cross-tenant replication"
}
func (storageCrossTenantRepl) Description() string {
	return "azurerm_storage_account without allow_cross_tenant_replication " +
		"= false permits object replication to storage accounts in other " +
		"Microsoft Entra tenants, enabling data exfiltration paths. Disable " +
		"cross-tenant replication."
}
func (storageCrossTenantRepl) Severity() ir.Severity { return ir.SeverityMedium }

func (storageCrossTenantRepl) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageCrossTenantRepl) Check(r ir.Resource) []ir.Finding {
	allowed, span, present, known := getBool(r, "allow_cross_tenant_replication")
	if present && !known {
		return nil
	}
	if present && !allowed {
		return nil
	}
	actual := "absent (default true)"
	if present {
		actual = "true"
	}
	return []ir.Finding{mkFinding(s, r, "allow_cross_tenant_replication",
		evidenceSpan(span, r.Span), actual,
		"allow_cross_tenant_replication = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-146: Storage account without blob versioning

// ---------------------------------------------------------------------------
// AEGIS-AZURE-147: Storage account without blob change feed
// ---------------------------------------------------------------------------

type storageNoChangeFeed struct{}

func (storageNoChangeFeed) ID() string { return "AEGIS-AZURE-147" }
func (storageNoChangeFeed) Title() string {
	return "Storage account without blob change feed"
}
func (storageNoChangeFeed) Description() string {
	return "azurerm_storage_account blob_properties without " +
		"change_feed_enabled = true records no ordered log of blob " +
		"create/update/delete events, blinding incident response to data " +
		"tampering. Enable the blob change feed."
}
func (storageNoChangeFeed) Severity() ir.Severity { return ir.SeverityLow }

func (storageNoChangeFeed) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoChangeFeed) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "blob_properties")
	if !present || !known || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "blob_properties.change_feed_enabled",
			evidenceSpan(ir.Span{}, r.Span), "absent (default false)",
			"blob_properties { change_feed_enabled = true }")}
	}
	cf, _, cpresent, cknown := blockBool(blks[0], "change_feed_enabled")
	if cpresent && !cknown {
		return nil
	}
	if cpresent && cf {
		return nil
	}
	actual := "absent (default false)"
	if cpresent {
		actual = "false"
	}
	return []ir.Finding{mkFinding(s, r, "blob_properties.change_feed_enabled",
		evidenceSpan(ir.Span{}, r.Span), actual,
		"change_feed_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-148: Storage account public network access (strict)
// ---------------------------------------------------------------------------

type storagePublicNetStrict struct{}

func (storagePublicNetStrict) ID() string { return "AEGIS-AZURE-148" }
func (storagePublicNetStrict) Title() string {
	return "Storage account with public network access (default)"
}
func (storagePublicNetStrict) Description() string {
	return "azurerm_storage_account without " +
		"public_network_access_enabled = false exposes the storage endpoint " +
		"to the internet by default. Disable public network access and use " +
		"private endpoints instead. (Strict complement of AEGIS-AZURE-006, " +
		"which covers an explicit true value.)"
}
func (storagePublicNetStrict) Severity() ir.Severity { return ir.SeverityHigh }

func (storagePublicNetStrict) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storagePublicNetStrict) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getBool(r, "public_network_access_enabled")
	if !present {
		return []ir.Finding{mkFinding(s, r, "public_network_access_enabled",
			evidenceSpan(ir.Span{}, r.Span), "absent (default true)",
			"public_network_access_enabled = false")}
	}
	if !known {
		return nil
	}
	// Present (true or false) is AEGIS-AZURE-006's domain; stay quiet here.
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-149: Storage account without network rules (strict)
// ---------------------------------------------------------------------------

type storageNoNetworkRules struct{}

func (storageNoNetworkRules) ID() string { return "AEGIS-AZURE-149" }
func (storageNoNetworkRules) Title() string {
	return "Storage account without network rules"
}
func (storageNoNetworkRules) Description() string {
	return "azurerm_storage_account without a network_rules block accepts " +
		"storage traffic from any network by default. Add network_rules " +
		"with default_action = \"Deny\" and explicit allow rules. (Strict " +
		"complement of AEGIS-AZURE-021, which covers an explicit Allow " +
		"default action.)"
}
func (storageNoNetworkRules) Severity() ir.Severity { return ir.SeverityMedium }

func (storageNoNetworkRules) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoNetworkRules) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "network_rules")
	if !present {
		return []ir.Finding{mkFinding(s, r, "network_rules",
			evidenceSpan(ir.Span{}, r.Span), "absent (default allow all)",
			"network_rules { default_action = \"Deny\" ... }")}
	}
	if !known || len(blks) == 0 {
		return nil
	}
	if _, _, aPresent, aKnown := blockString(blks[0], "default_action"); aPresent && !aKnown {
		return nil
	}
	// Present: AEGIS-AZURE-021 covers an explicit Allow; anything else
	// closes the strict gap, so the two rules never double-fire.
	return nil
}
