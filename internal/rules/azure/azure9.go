// Package azure — storage account hardening rules, round 2 (AEGIS-AZURE-119..126).
//
// Absent-attribute policy for this file (documented per the pack contract):
// these "without X" hardening rules treat an absent attribute as a finding,
// because the azurerm provider defaults are the insecure ones (public blob
// access on, TLS 1.0, shared key access on, no SAS policy). Present-but-
// unresolved values still yield NO finding.
package azure

import (
	"sort"
	"strings"

	"aegis/internal/graph"
	"aegis/internal/ir"
)

// Azure9Rules returns storage hardening rules in ID order.
func Azure9Rules() []ir.Rule {
	return []ir.Rule{
		storageNestedItemsPublic{}, // AEGIS-AZURE-119
		storageQueueNoLogging2{},   // AEGIS-AZURE-120
		storageMinTLS2{},           // AEGIS-AZURE-121
		storageBlobPublic2{},       // AEGIS-AZURE-122
		storageSharedKey2{},        // AEGIS-AZURE-123
		storageNoPrivateEndpoint{}, // AEGIS-AZURE-124
		storageNoSasPolicy{},       // AEGIS-AZURE-125
		storageBlobSoftDelete2{},   // AEGIS-AZURE-126
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-119: Storage account allows public blob/nested item access
// ---------------------------------------------------------------------------

type storageNestedItemsPublic struct{}

func (storageNestedItemsPublic) ID() string { return "AEGIS-AZURE-119" }
func (storageNestedItemsPublic) Title() string {
	return "Storage account allows public nested item access"
}
func (storageNestedItemsPublic) Description() string {
	return "azurerm_storage_account with allow_blob_public_access = true " +
		"(the provider default) or allow_nested_items_to_be_public = true " +
		"exposes blob data to anonymous requests. Disable public access " +
		"unless public content delivery is intended."
}
func (storageNestedItemsPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (storageNestedItemsPublic) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNestedItemsPublic) Check(r ir.Resource) []ir.Finding {
	if pub, span, present, known := getBool(r, "allow_nested_items_to_be_public"); present {
		if !known {
			return nil
		}
		if pub {
			return []ir.Finding{mkFinding(s, r, "allow_nested_items_to_be_public", span,
				"true", "allow_nested_items_to_be_public = false")}
		}
		return nil
	}
	// Provider default for allow_blob_public_access is true.
	pub, span, present, known := getBool(r, "allow_blob_public_access")
	if !present {
		return []ir.Finding{mkFinding(s, r, "allow_blob_public_access",
			evidenceSpan(ir.Span{}, r.Span), "absent (default true)",
			"allow_blob_public_access = false")}
	}
	if !known {
		return nil
	}
	if pub {
		return []ir.Finding{mkFinding(s, r, "allow_blob_public_access", span,
			"true", "allow_blob_public_access = false")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-120: Storage account without queue logging (strict)
// ---------------------------------------------------------------------------

type storageQueueNoLogging2 struct{}

func (storageQueueNoLogging2) ID() string { return "AEGIS-AZURE-120" }
func (storageQueueNoLogging2) Title() string {
	return "Storage account without queue logging"
}
func (storageQueueNoLogging2) Description() string {
	return "azurerm_storage_account queue_properties without a logging " +
		"block loses the audit trail for queue operations. Enable queue " +
		"logging with read, write and delete coverage."
}
func (storageQueueNoLogging2) Severity() ir.Severity { return ir.SeverityMedium }

func (storageQueueNoLogging2) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageQueueNoLogging2) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "queue_properties")
	if !present {
		return []ir.Finding{mkFinding(s, r, "queue_properties.logging",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"queue_properties { logging { read = true write = true delete = true } }")}
	}
	if !known {
		return nil
	}
	for _, b := range blks {
		if len(blockList(b, "logging")) > 0 {
			return nil
		}
	}
	return []ir.Finding{mkFinding(s, r, "queue_properties.logging",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"logging { read = true write = true delete = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-121: Storage account not using latest TLS (strict)
// ---------------------------------------------------------------------------

type storageMinTLS2 struct{}

func (storageMinTLS2) ID() string { return "AEGIS-AZURE-121" }
func (storageMinTLS2) Title() string {
	return "Storage account not using latest TLS version"
}
func (storageMinTLS2) Description() string {
	return "azurerm_storage_account without min_tls_version = \"TLS1_2\" " +
		"(the provider default is TLS1_0) permits deprecated TLS. Require " +
		"TLS 1.2 or higher."
}
func (storageMinTLS2) Severity() ir.Severity { return ir.SeverityMedium }

func (storageMinTLS2) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageMinTLS2) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "min_tls_version")
	if !present {
		return []ir.Finding{mkFinding(s, r, "min_tls_version",
			evidenceSpan(ir.Span{}, r.Span), "absent (default TLS1_0)",
			"min_tls_version = \"TLS1_2\"")}
	}
	if !known {
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
// AEGIS-AZURE-122: Storage blobs allow public access (strict)
// ---------------------------------------------------------------------------

type storageBlobPublic2 struct{}

func (storageBlobPublic2) ID() string { return "AEGIS-AZURE-122" }
func (storageBlobPublic2) Title() string {
	return "Storage blobs allow public access"
}
func (storageBlobPublic2) Description() string {
	return "azurerm_storage_account with allow_blob_public_access = true " +
		"(the provider default) exposes blob data to anonymous requests. " +
		"Set allow_blob_public_access = false."
}
func (storageBlobPublic2) Severity() ir.Severity { return ir.SeverityHigh }

func (storageBlobPublic2) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageBlobPublic2) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "allow_blob_public_access")
	if !present {
		return []ir.Finding{mkFinding(s, r, "allow_blob_public_access",
			evidenceSpan(ir.Span{}, r.Span), "absent (default true)",
			"allow_blob_public_access = false")}
	}
	if !known {
		return nil
	}
	if pub {
		return []ir.Finding{mkFinding(s, r, "allow_blob_public_access", span,
			"true", "allow_blob_public_access = false")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-123: Storage account with shared key access (strict)
// ---------------------------------------------------------------------------

type storageSharedKey2 struct{}

func (storageSharedKey2) ID() string { return "AEGIS-AZURE-123" }
func (storageSharedKey2) Title() string {
	return "Storage account allows shared key access"
}
func (storageSharedKey2) Description() string {
	return "azurerm_storage_account with shared_access_key_enabled = true " +
		"(the provider default) permits storage account key " +
		"authentication. Prefer Microsoft Entra ID and disable shared key access."
}
func (storageSharedKey2) Severity() ir.Severity { return ir.SeverityMedium }

func (storageSharedKey2) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageSharedKey2) Check(r ir.Resource) []ir.Finding {
	shared, span, present, known := getBool(r, "shared_access_key_enabled")
	if !present {
		return []ir.Finding{mkFinding(s, r, "shared_access_key_enabled",
			evidenceSpan(ir.Span{}, r.Span), "absent (default true)",
			"shared_access_key_enabled = false")}
	}
	if !known {
		return nil
	}
	if shared {
		return []ir.Finding{mkFinding(s, r, "shared_access_key_enabled", span,
			"true", "shared_access_key_enabled = false")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-124: Storage account without private endpoint
// ---------------------------------------------------------------------------

type storageNoPrivateEndpoint struct{}

func (storageNoPrivateEndpoint) ID() string { return "AEGIS-AZURE-124" }
func (storageNoPrivateEndpoint) Title() string {
	return "Storage account without private endpoint"
}
func (storageNoPrivateEndpoint) Description() string {
	return "azurerm_storage_account with no azurerm_private_endpoint " +
		"targeting it is reachable over the public endpoint. Connect it " +
		"via a private endpoint on the storage subresource (blob, dfs, " +
		"queue, table, or file)."
}
func (storageNoPrivateEndpoint) Severity() ir.Severity { return ir.SeverityMedium }

func (storageNoPrivateEndpoint) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (storageNoPrivateEndpoint) Check(ir.Resource) []ir.Finding { return nil }

func (s storageNoPrivateEndpoint) CheckAll(resources []ir.Resource) []ir.Finding {
	g := graph.Build(resources)
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	var out []ir.Finding
	for _, r := range sorted {
		if r.Type != "azurerm_storage_account" {
			continue
		}
		linked := false
		for _, e := range g.InEdges(r.Address()) {
			if from, ok := g.Resource(e.From); ok &&
				from.Type == "azurerm_private_endpoint" {
				linked = true
				break
			}
		}
		if !linked {
			out = append(out, mkFinding(s, r, "private_endpoint",
				evidenceSpan(ir.Span{}, r.Span),
				"no azurerm_private_endpoint targets this account",
				"azurerm_private_endpoint { private_service_connection { private_connection_resource_id = azurerm_storage_account.this.id subresource_names = [\"blob\"] } }"))
		}
	}
	return out
}

var _ ir.CrossResourceRule = storageNoPrivateEndpoint{}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-125: Storage account without SAS expiry policy
// ---------------------------------------------------------------------------

type storageNoSasPolicy struct{}

func (storageNoSasPolicy) ID() string { return "AEGIS-AZURE-125" }
func (storageNoSasPolicy) Title() string {
	return "Storage account without SAS expiry policy"
}
func (storageNoSasPolicy) Description() string {
	return "azurerm_storage_account without a sas_policy block issues " +
		"shared access signatures with no enforced expiry. Set " +
		"sas_policy { expiration_period and expiration_action } to bound " +
		"SAS lifetimes."
}
func (storageNoSasPolicy) Severity() ir.Severity { return ir.SeverityLow }

func (storageNoSasPolicy) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageNoSasPolicy) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "sas_policy")
	if !present {
		return []ir.Finding{mkFinding(s, r, "sas_policy",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"sas_policy { expiration_period = \"90.00:00:00\" expiration_action = \"Log\" }")}
	}
	if !known || len(blks) == 0 {
		return nil
	}
	if _, _, ep, _ := blockString(blks[0], "expiration_period"); ep {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "sas_policy.expiration_period",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"expiration_period = \"90.00:00:00\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-126: Storage account without blob soft delete (strict)
// ---------------------------------------------------------------------------

type storageBlobSoftDelete2 struct{}

func (storageBlobSoftDelete2) ID() string { return "AEGIS-AZURE-126" }
func (storageBlobSoftDelete2) Title() string {
	return "Storage account without blob soft delete"
}
func (storageBlobSoftDelete2) Description() string {
	return "azurerm_storage_account blob_properties without " +
		"delete_retention_policy enabled cannot recover accidentally " +
		"deleted blobs. Enable soft delete with a retention period."
}
func (storageBlobSoftDelete2) Severity() ir.Severity { return ir.SeverityMedium }

func (storageBlobSoftDelete2) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}

func (s storageBlobSoftDelete2) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "blob_properties")
	if !present || !known || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "blob_properties.delete_retention_policy",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"blob_properties { delete_retention_policy { days = 7 } }")}
	}
	drp, ok := blks[0]["delete_retention_policy"]
	if !ok || !drp.Known {
		return []ir.Finding{mkFinding(s, r, "blob_properties.delete_retention_policy",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"delete_retention_policy { days = 7 }")}
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
	if !ok || !dv.Known {
		return []ir.Finding{mkFinding(s, r, "blob_properties.delete_retention_policy.days",
			drp.Span, "absent", "days = 7")}
	}
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
		dv.Span, "0", "days = 7")}
}
