// Package azure — data platform & AI services round (AEGIS-AZURE-298..313).
//
// Covers Data Factory (public network, CMK, managed VNet, identity),
// Synapse (data exfiltration, managed VNet, CMK, AAD admin), Databricks
// (public network, CMK, no-public-IP), IoT Hub (IP filter, public
// network, TLS, file upload, fallback route, endpoint auth), Cognitive
// Services (public network, CMK, local auth, network rules) and Redis
// (TLS, non-SSL port, public network).
//
// Absent-attribute policy for this file: absent yields a finding when the
// provider default is insecure. Present-but-unresolved yields NO finding.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure21Rules returns data platform & AI services rules in ID order.
func Azure21Rules() []ir.Rule {
	return []ir.Rule{
		adfNoCMK{},           // AEGIS-AZURE-299
		adfNoManagedVNet{},   // AEGIS-AZURE-300
		synapseDataExfil{},   // AEGIS-AZURE-301
		synapseNoCMK{},       // AEGIS-AZURE-302
		databricksInfraEnc{},  // AEGIS-AZURE-303
		databricksNoPublicIP{}, // AEGIS-AZURE-304
		iotHubNoIPFilter{},   // AEGIS-AZURE-305
		iotHubSAPRegWrite{},  // AEGIS-AZURE-306
		iotHubMinTLS{},       // AEGIS-AZURE-307
		iotHubFallbackRoute{}, // AEGIS-AZURE-308
		cognitiveNetACLs{},   // AEGIS-AZURE-309
		cognitiveNoCMK{},     // AEGIS-AZURE-310
		cognitiveLocalAuth{}, // AEGIS-AZURE-311
		redisPublicNet{},      // AEGIS-AZURE-313
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-298: Data Factory with public network access

// ---------------------------------------------------------------------------
// AEGIS-AZURE-299: Data Factory without customer-managed key
// ---------------------------------------------------------------------------

type adfNoCMK struct{}

func (adfNoCMK) ID() string { return "AEGIS-AZURE-299" }
func (adfNoCMK) Title() string {
	return "Data Factory without customer-managed key"
}
func (adfNoCMK) Description() string {
	return "azurerm_data_factory without a customer_managed_key_id " +
		"relies on Microsoft-managed keys for pipeline secrets and " +
		"metadata. Configure CMK in Key Vault."
}
func (adfNoCMK) Severity() ir.Severity { return ir.SeverityMedium }

func (adfNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_data_factory"
}

func (s adfNoCMK) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["customer_managed_key_id"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "customer_managed_key_id", r.Span,
			"absent (Microsoft-managed keys)",
			"customer_managed_key_id = \"...\"")}
	}
	if !v.Known {
		return nil
	}
	sv, kok := v.AsString()
	if !kok || strings.TrimSpace(sv) == "" {
		return []ir.Finding{mkFinding(s, r, "customer_managed_key_id", v.Span,
			"empty", "customer_managed_key_id = \"...\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-300: Data Factory without managed virtual network
// ---------------------------------------------------------------------------

type adfNoManagedVNet struct{}

func (adfNoManagedVNet) ID() string { return "AEGIS-AZURE-300" }
func (adfNoManagedVNet) Title() string {
	return "Data Factory without managed virtual network"
}
func (adfNoManagedVNet) Description() string {
	return "azurerm_data_factory without managed_virtual_network_enabled " +
		"= true runs integration runtimes outside an isolated " +
		"network. Enable the managed virtual network for private " +
		"data movement."
}
func (adfNoManagedVNet) Severity() ir.Severity { return ir.SeverityMedium }

func (adfNoManagedVNet) AppliesTo(resType string) bool {
	return resType == "azurerm_data_factory"
}

func (s adfNoManagedVNet) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "managed_virtual_network_enabled",
		"managed_virtual_network_enabled = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-301: Synapse workspace allowing data exfiltration
// ---------------------------------------------------------------------------

type synapseDataExfil struct{}

func (synapseDataExfil) ID() string { return "AEGIS-AZURE-301" }
func (synapseDataExfil) Title() string {
	return "Synapse workspace allowing data exfiltration"
}
func (synapseDataExfil) Description() string {
	return "azurerm_synapse_workspace with " +
		"data_exfiltration_protection_enabled = false (or absent) lets " +
		"pipelines write to arbitrary external targets. Enable data " +
		"exfiltration protection."
}
func (synapseDataExfil) Severity() ir.Severity { return ir.SeverityHigh }

func (synapseDataExfil) AppliesTo(resType string) bool {
	return resType == "azurerm_synapse_workspace"
}

func (s synapseDataExfil) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "data_exfiltration_protection_enabled",
		"data_exfiltration_protection_enabled = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-302: Synapse workspace without customer-managed key
// ---------------------------------------------------------------------------

type synapseNoCMK struct{}

func (synapseNoCMK) ID() string { return "AEGIS-AZURE-302" }
func (synapseNoCMK) Title() string {
	return "Synapse workspace without customer-managed key"
}
func (synapseNoCMK) Description() string {
	return "azurerm_synapse_workspace without a " +
		"customer_managed_key block relies on Microsoft-managed keys " +
		"for workspace data. Configure CMK in Key Vault."
}
func (synapseNoCMK) Severity() ir.Severity { return ir.SeverityMedium }

func (synapseNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_synapse_workspace"
}

func (s synapseNoCMK) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "customer_managed_key")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "customer_managed_key",
		evidenceSpan(span, r.Span), "absent (Microsoft-managed keys)",
		"customer_managed_key { key_vault_key_id = \"...\" }")}
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AEGIS-AZURE-303: Databricks workspace without infrastructure encryption
// ---------------------------------------------------------------------------

type databricksInfraEnc struct{}

func (databricksInfraEnc) ID() string { return "AEGIS-AZURE-303" }
func (databricksInfraEnc) Title() string {
	return "Databricks workspace without infrastructure encryption"
}
func (databricksInfraEnc) Description() string {
	return "azurerm_databricks_workspace without " +
		"infrastructure_encryption_enabled = true leaves the managed " +
		"resource group disks unencrypted with a second layer. Enable " +
		"infrastructure (double) encryption."
}
func (databricksInfraEnc) Severity() ir.Severity { return ir.SeverityMedium }

func (databricksInfraEnc) AppliesTo(resType string) bool {
	return resType == "azurerm_databricks_workspace"
}

func (s databricksInfraEnc) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "infrastructure_encryption_enabled",
		"infrastructure_encryption_enabled = true")
}
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AEGIS-AZURE-304: Databricks workspace with public IPs on clusters
// ---------------------------------------------------------------------------

type databricksNoPublicIP struct{}

func (databricksNoPublicIP) ID() string { return "AEGIS-AZURE-304" }
func (databricksNoPublicIP) Title() string {
	return "Databricks workspace with public IPs on clusters"
}
func (databricksNoPublicIP) Description() string {
	return "azurerm_databricks_workspace custom_parameters without " +
		"no_public_ip = true provisions cluster nodes with public IP " +
		"addresses. Disable public IPs (secure cluster connectivity)."
}
func (databricksNoPublicIP) Severity() ir.Severity { return ir.SeverityMedium }

func (databricksNoPublicIP) AppliesTo(resType string) bool {
	return resType == "azurerm_databricks_workspace"
}

func (s databricksNoPublicIP) Check(r ir.Resource) []ir.Finding {
	cps, span, present, known := getBlocks(r, "custom_parameters")
	if !present || !known {
		return []ir.Finding{mkFinding(s, r, "custom_parameters",
			evidenceSpan(span, r.Span), "absent (public IPs by default)",
			"custom_parameters { no_public_ip = true }")}
	}
	for _, cp := range cps {
		en, _, p, k := blockBool(cp, "no_public_ip")
		if p && !k {
			return nil
		}
		if p && en {
			return nil
		}
		return []ir.Finding{mkFinding(s, r, "custom_parameters",
			evidenceSpan(span, r.Span), "no_public_ip not enabled",
			"custom_parameters { no_public_ip = true }")}
	}
	return nil
}
// ---------------------------------------------------------------------------
// AEGIS-AZURE-305: IoT Hub without IP filter
// ---------------------------------------------------------------------------

type iotHubNoIPFilter struct{}

func (iotHubNoIPFilter) ID() string { return "AEGIS-AZURE-305" }
func (iotHubNoIPFilter) Title() string {
	return "IoT Hub with public access and no IP filter"
}
func (iotHubNoIPFilter) Description() string {
	return "azurerm_iothub with public_network_access_enabled and no " +
		"ip_filter_rule blocks accepts device connections from any " +
		"IP. When public access is required, restrict it with " +
		"ip_filter_rule entries."
}
func (iotHubNoIPFilter) Severity() ir.Severity { return ir.SeverityMedium }

func (iotHubNoIPFilter) AppliesTo(resType string) bool {
	return resType == "azurerm_iothub"
}

func (s iotHubNoIPFilter) Check(r ir.Resource) []ir.Finding {
	pub, _, ppresent, pknown := getBool(r, "public_network_access_enabled")
	if ppresent && !pknown {
		return nil
	}
	if ppresent && !pub {
		return nil
	}
	blks, _, present, known := getBlocks(r, "ip_filter_rule")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	actual := "absent"
	if !ppresent {
		actual = "absent (public by default)"
	}
	return []ir.Finding{mkFinding(s, r, "ip_filter_rule", r.Span,
		actual, "ip_filter_rule { ip_mask = \"<cidr>\", action = \"Accept\" }")}
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AEGIS-AZURE-306: IoT Hub shared access policy with registry write
// ---------------------------------------------------------------------------

type iotHubSAPRegWrite struct{}

func (iotHubSAPRegWrite) ID() string { return "AEGIS-AZURE-306" }
func (iotHubSAPRegWrite) Title() string {
	return "IoT Hub shared access policy with registry write"
}
func (iotHubSAPRegWrite) Description() string {
	return "azurerm_iothub_shared_access_policy with registry_write = " +
		"true grants device-registry modification rights. Grant only " +
		"the permissions each integration needs."
}
func (iotHubSAPRegWrite) Severity() ir.Severity { return ir.SeverityMedium }

func (iotHubSAPRegWrite) AppliesTo(resType string) bool {
	return resType == "azurerm_iothub_shared_access_policy"
}

func (s iotHubSAPRegWrite) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "registry_write")
	if !present || !known {
		return nil // default false: secure
	}
	if !en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "registry_write", span,
		"true", "registry_write = false")}
}
// ---------------------------------------------------------------------------
// AEGIS-AZURE-307: IoT Hub below TLS 1.2
// ---------------------------------------------------------------------------

type iotHubMinTLS struct{}

func (iotHubMinTLS) ID() string { return "AEGIS-AZURE-307" }
func (iotHubMinTLS) Title() string {
	return "IoT Hub below TLS 1.2"
}
func (iotHubMinTLS) Description() string {
	return "azurerm_iothub with min_tls_version other than \"1.2\" " +
		"permits weaker protocol versions for device connections. " +
		"Enforce TLS 1.2."
}
func (iotHubMinTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (iotHubMinTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_iothub"
}

func (s iotHubMinTLS) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "min_tls_version")
	if !present || !known {
		return nil
	}
	if ver == "1.2" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "min_tls_version", span,
		ver, "min_tls_version = \"1.2\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-308: IoT Hub without fallback route
// ---------------------------------------------------------------------------

type iotHubFallbackRoute struct{}

func (iotHubFallbackRoute) ID() string { return "AEGIS-AZURE-308" }
func (iotHubFallbackRoute) Title() string {
	return "IoT Hub without fallback route"
}
func (iotHubFallbackRoute) Description() string {
	return "azurerm_iothub without a fallback_route block silently " +
		"drops device messages that match no route, hiding telemetry " +
		"loss. Define a fallback route to a monitored endpoint."
}
func (iotHubFallbackRoute) Severity() ir.Severity { return ir.SeverityLow }

func (iotHubFallbackRoute) AppliesTo(resType string) bool {
	return resType == "azurerm_iothub"
}

func (s iotHubFallbackRoute) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "fallback_route")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "fallback_route",
		evidenceSpan(span, r.Span), "absent (unmatched messages dropped)",
		"fallback_route { source = \"DeviceMessages\", enabled = true }")}
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AEGIS-AZURE-309: Cognitive Services with permissive network ACLs
// ---------------------------------------------------------------------------

type cognitiveNetACLs struct{}

func (cognitiveNetACLs) ID() string { return "AEGIS-AZURE-309" }
func (cognitiveNetACLs) Title() string {
	return "Cognitive Services with permissive network ACLs"
}
func (cognitiveNetACLs) Description() string {
	return "azurerm_cognitive_account network_acls with default_action " +
		"other than \"Deny\" accepts AI API traffic from any network. " +
		"Set default_action = \"Deny\" with explicit allowances."
}
func (cognitiveNetACLs) Severity() ir.Severity { return ir.SeverityMedium }

func (cognitiveNetACLs) AppliesTo(resType string) bool {
	return resType == "azurerm_cognitive_account"
}

func (s cognitiveNetACLs) Check(r ir.Resource) []ir.Finding {
	acls, span, present, known := getBlocks(r, "network_acls")
	if !present || !known {
		return nil
	}
	for _, a := range acls {
		act, _, p, k := blockString(a, "default_action")
		if p && !k {
			return nil
		}
		if !p || !strings.EqualFold(strings.TrimSpace(act), "Deny") {
			actual := "absent"
			if p {
				actual = act
			}
			return []ir.Finding{mkFinding(s, r, "network_acls",
				evidenceSpan(span, r.Span), actual,
				"network_acls { default_action = \"Deny\" }")}
		}
	}
	return nil
}
// ---------------------------------------------------------------------------
// AEGIS-AZURE-310: Cognitive Services without customer-managed key
// ---------------------------------------------------------------------------

type cognitiveNoCMK struct{}

func (cognitiveNoCMK) ID() string { return "AEGIS-AZURE-310" }
func (cognitiveNoCMK) Title() string {
	return "Cognitive Services account without customer-managed key"
}
func (cognitiveNoCMK) Description() string {
	return "azurerm_cognitive_account without a customer_managed_key " +
		"block relies on Microsoft-managed keys for stored data. " +
		"Configure CMK in Key Vault."
}
func (cognitiveNoCMK) Severity() ir.Severity { return ir.SeverityMedium }

func (cognitiveNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_cognitive_account"
}

func (s cognitiveNoCMK) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "customer_managed_key")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "customer_managed_key",
		evidenceSpan(span, r.Span), "absent (Microsoft-managed keys)",
		"customer_managed_key { key_vault_key_id = \"...\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-311: Cognitive Services with local auth enabled
// ---------------------------------------------------------------------------

type cognitiveLocalAuth struct{}

func (cognitiveLocalAuth) ID() string { return "AEGIS-AZURE-311" }
func (cognitiveLocalAuth) Title() string {
	return "Cognitive Services account with local authentication"
}
func (cognitiveLocalAuth) Description() string {
	return "azurerm_cognitive_account without " +
		"local_auth_enabled = false permits key-based authentication " +
		"to AI APIs. Disable local auth and use Entra ID."
}
func (cognitiveLocalAuth) Severity() ir.Severity { return ir.SeverityMedium }

func (cognitiveLocalAuth) AppliesTo(resType string) bool {
	return resType == "azurerm_cognitive_account"
}

func (s cognitiveLocalAuth) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "local_auth_enabled")
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
	return []ir.Finding{mkFinding(s, r, "local_auth_enabled",
		evidenceSpan(span, r.Span), actual, "local_auth_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-312: Redis cache below TLS 1.2

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AEGIS-AZURE-313: Redis cache with public network access
// ---------------------------------------------------------------------------

type redisPublicNet struct{}

func (redisPublicNet) ID() string { return "AEGIS-AZURE-313" }
func (redisPublicNet) Title() string {
	return "Redis cache with public network access enabled"
}
func (redisPublicNet) Description() string {
	return "azurerm_redis_cache with public_network_access_enabled " +
		"(the provider default) exposes the cache endpoint over the " +
		"public internet. Disable it and use private endpoints."
}
func (redisPublicNet) Severity() ir.Severity { return ir.SeverityHigh }

func (redisPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_redis_cache"
}

func (s redisPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_redis_cache")
}
