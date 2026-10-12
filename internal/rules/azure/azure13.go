// Package azure — new-service coverage round (AEGIS-AZURE-150..169).
//
// Fills gaps in services with no prior coverage: Function Apps, API
// Management, Data Factory, Synapse, Databricks, Event Grid, Machine
// Learning, App Configuration, Automation, Search, Cognitive Services,
// IoT Hub, and PostgreSQL flexible servers.
//
// Absent-attribute policy for this file: an absent attribute yields a
// finding when the provider default is the insecure one (public network
// access on for the PaaS services below, HTTPS-only off for Function
// Apps). Present-but-unresolved values yield NO finding.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure13Rules returns new-service coverage rules in ID order.
func Azure13Rules() []ir.Rule {
	return []ir.Rule{
		funcAppNoHTTPS{},        // AEGIS-AZURE-150
		funcAppNoIPRestrict{},   // AEGIS-AZURE-151
		funcAppNoIdentity{},     // AEGIS-AZURE-152
		apimNoVNet{},            // AEGIS-AZURE-153
		apimPublicNet{},         // AEGIS-AZURE-154
		dataFactoryPublicNet{},  // AEGIS-AZURE-155
		synapseNoManagedVNet{},  // AEGIS-AZURE-156
		synapseNoExfilProtect{}, // AEGIS-AZURE-157
		databricksNoCMK{},       // AEGIS-AZURE-158
		databricksPublicNet{},   // AEGIS-AZURE-159
		eventGridPublicNet{},    // AEGIS-AZURE-160
		eventGridLocalAuth{},    // AEGIS-AZURE-161
		mlWorkspacePublicNet{},  // AEGIS-AZURE-162
		appConfigNoPurge{},      // AEGIS-AZURE-163
		appConfigPublicNet{},    // AEGIS-AZURE-164
		automationPublicNet{},   // AEGIS-AZURE-165
		searchPublicNet{},       // AEGIS-AZURE-166
		cognitivePublicNet{},    // AEGIS-AZURE-167
		iotHubPublicNet{},       // AEGIS-AZURE-168
		postgresFlexPublicNet{}, // AEGIS-AZURE-169
	}
}

// publicNetOpen reports a finding when a public-network-access attribute is
// absent (provider default: enabled) or explicitly true. usedAttr is the
// attribute name on the resource; resourceName names the service for the
// expected-text.
func publicNetOpen(rule ir.Rule, r ir.Resource, usedAttr, resourceName string) []ir.Finding {
	open, span, present, known := getBool(r, usedAttr)
	if present && !known {
		return nil
	}
	if present && !open {
		return nil
	}
	actual := "true"
	if !present {
		actual = "absent (provider default: enabled)"
	}
	return []ir.Finding{mkFinding(rule, r, usedAttr,
		evidenceSpan(span, r.Span), actual,
		usedAttr+" = false on "+resourceName)}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-150: Function App without HTTPS-only
// ---------------------------------------------------------------------------

type funcAppNoHTTPS struct{}

func (funcAppNoHTTPS) ID() string { return "AEGIS-AZURE-150" }
func (funcAppNoHTTPS) Title() string {
	return "Function App without HTTPS-only"
}
func (funcAppNoHTTPS) Description() string {
	return "azurerm_function_app / azurerm_linux_function_app without " +
		"https_only = true serves traffic over plain HTTP, exposing " +
		"function invocations and keys to interception. Enforce HTTPS-only."
}
func (funcAppNoHTTPS) Severity() ir.Severity { return ir.SeverityHigh }

func (funcAppNoHTTPS) AppliesTo(resType string) bool {
	return resType == "azurerm_function_app" ||
		resType == "azurerm_linux_function_app"
}

func (s funcAppNoHTTPS) Check(r ir.Resource) []ir.Finding {
	only, span, present, known := getBool(r, "https_only")
	if present && !known {
		return nil
	}
	if present && only {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{mkFinding(s, r, "https_only",
		evidenceSpan(span, r.Span), actual, "https_only = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-151: Function App without IP restrictions
// ---------------------------------------------------------------------------

type funcAppNoIPRestrict struct{}

func (funcAppNoIPRestrict) ID() string { return "AEGIS-AZURE-151" }
func (funcAppNoIPRestrict) Title() string {
	return "Function App without IP restrictions"
}
func (funcAppNoIPRestrict) Description() string {
	return "azurerm_function_app / azurerm_linux_function_app without " +
		"site_config.ip_restriction accepts invocations from any source IP. " +
		"Restrict the function endpoint to known callers."
}
func (funcAppNoIPRestrict) Severity() ir.Severity { return ir.SeverityMedium }

func (funcAppNoIPRestrict) AppliesTo(resType string) bool {
	return resType == "azurerm_function_app" ||
		resType == "azurerm_linux_function_app"
}

func (s funcAppNoIPRestrict) Check(r ir.Resource) []ir.Finding {
	sc, span, present, known := getBlocks(r, "site_config")
	if present && !known {
		return nil
	}
	if present {
		for _, b := range sc {
			if hasNonEmptyBlock(b, "ip_restriction") {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "site_config",
		evidenceSpan(span, r.Span), "no ip_restriction block",
		"site_config { ip_restriction { ip_address = \"<cidr>\" } }")}
}

// hasNonEmptyBlock reports whether a block map carries a non-empty nested
// block list under name.
func hasNonEmptyBlock(m map[string]ir.Value, name string) bool {
	v, ok := m[name]
	if !ok || !v.Known {
		return false
	}
	if _, ok := v.AsMap(); ok {
		return true
	}
	l, ok := v.AsList()
	return ok && len(l) > 0
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-152: Function App without managed identity
// ---------------------------------------------------------------------------

type funcAppNoIdentity struct{}

func (funcAppNoIdentity) ID() string { return "AEGIS-AZURE-152" }
func (funcAppNoIdentity) Title() string {
	return "Function App without managed identity"
}
func (funcAppNoIdentity) Description() string {
	return "azurerm_function_app / azurerm_linux_function_app without an " +
		"identity block cannot use managed identities and tends to rely on " +
		"stored credentials or connection strings. Enable a system-assigned " +
		"identity and grant it least-privilege RBAC."
}
func (funcAppNoIdentity) Severity() ir.Severity { return ir.SeverityMedium }

func (funcAppNoIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_function_app" ||
		resType == "azurerm_linux_function_app"
}

func (s funcAppNoIdentity) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "identity")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "identity",
		evidenceSpan(span, r.Span), "absent (no managed identity)",
		"identity { type = \"SystemAssigned\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-153: API Management without virtual network
// ---------------------------------------------------------------------------

type apimNoVNet struct{}

func (apimNoVNet) ID() string { return "AEGIS-AZURE-153" }
func (apimNoVNet) Title() string {
	return "API Management without virtual network integration"
}
func (apimNoVNet) Description() string {
	return "azurerm_api_management without virtual_network_type set to " +
		"Internal or External is not isolated in a VNet, so the gateway " +
		"cannot be shielded behind private networking. Deploy the gateway " +
		"into a virtual network."
}
func (apimNoVNet) Severity() ir.Severity { return ir.SeverityMedium }

func (apimNoVNet) AppliesTo(resType string) bool {
	return resType == "azurerm_api_management"
}

func (s apimNoVNet) Check(r ir.Resource) []ir.Finding {
	vnt, span, present, known := getString(r, "virtual_network_type")
	if present && !known {
		return nil
	}
	if present && !strings.EqualFold(strings.TrimSpace(vnt), "None") && strings.TrimSpace(vnt) != "" {
		return nil
	}
	actual := "absent (default: None)"
	if present {
		actual = vnt
	}
	return []ir.Finding{mkFinding(s, r, "virtual_network_type",
		evidenceSpan(span, r.Span), actual,
		"virtual_network_type = \"Internal\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-154: API Management with public network access
// ---------------------------------------------------------------------------

type apimPublicNet struct{}

func (apimPublicNet) ID() string { return "AEGIS-AZURE-154" }
func (apimPublicNet) Title() string {
	return "API Management with public network access enabled"
}
func (apimPublicNet) Description() string {
	return "azurerm_api_management with public_network_access_enabled " +
		"(the provider default) exposes the management plane and gateway " +
		"to the internet. Disable public network access when the gateway " +
		"is VNet-integrated."
}
func (apimPublicNet) Severity() ir.Severity { return ir.SeverityMedium }

func (apimPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_api_management"
}

func (s apimPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_api_management")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-155: Data Factory with public network access
// ---------------------------------------------------------------------------

type dataFactoryPublicNet struct{}

func (dataFactoryPublicNet) ID() string { return "AEGIS-AZURE-155" }
func (dataFactoryPublicNet) Title() string {
	return "Data Factory with public network access enabled"
}
func (dataFactoryPublicNet) Description() string {
	return "azurerm_data_factory with public_network_enabled (the provider " +
		"default) exposes the data factory endpoints to the internet. " +
		"Disable public network access and use private endpoints."
}
func (dataFactoryPublicNet) Severity() ir.Severity { return ir.SeverityMedium }

func (dataFactoryPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_data_factory"
}

func (s dataFactoryPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_enabled", "azurerm_data_factory")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-156: Synapse workspace without managed virtual network
// ---------------------------------------------------------------------------

type synapseNoManagedVNet struct{}

func (synapseNoManagedVNet) ID() string { return "AEGIS-AZURE-156" }
func (synapseNoManagedVNet) Title() string {
	return "Synapse workspace without managed virtual network"
}
func (synapseNoManagedVNet) Description() string {
	return "azurerm_synapse_workspace without managed_virtual_network_enabled " +
		"= true runs Spark/SQL pools outside an isolated managed VNet, " +
		"limiting network isolation for analytics workloads. Enable the " +
		"managed virtual network."
}
func (synapseNoManagedVNet) Severity() ir.Severity { return ir.SeverityHigh }

func (synapseNoManagedVNet) AppliesTo(resType string) bool {
	return resType == "azurerm_synapse_workspace"
}

func (s synapseNoManagedVNet) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "managed_virtual_network_enabled")
	if present && !known {
		return nil
	}
	if present && en {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{mkFinding(s, r, "managed_virtual_network_enabled",
		evidenceSpan(span, r.Span), actual,
		"managed_virtual_network_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-157: Synapse workspace without data exfiltration protection
// ---------------------------------------------------------------------------

type synapseNoExfilProtect struct{}

func (synapseNoExfilProtect) ID() string { return "AEGIS-AZURE-157" }
func (synapseNoExfilProtect) Title() string {
	return "Synapse workspace without data exfiltration protection"
}
func (synapseNoExfilProtect) Description() string {
	return "azurerm_synapse_workspace without " +
		"data_exfiltration_protection_enabled = true allows workspace " +
		"managed private endpoints to reach unapproved targets, enabling " +
		"data exfiltration. Enable data exfiltration protection."
}
func (synapseNoExfilProtect) Severity() ir.Severity { return ir.SeverityMedium }

func (synapseNoExfilProtect) AppliesTo(resType string) bool {
	return resType == "azurerm_synapse_workspace"
}

func (s synapseNoExfilProtect) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "data_exfiltration_protection_enabled")
	if present && !known {
		return nil
	}
	if present && en {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{mkFinding(s, r, "data_exfiltration_protection_enabled",
		evidenceSpan(span, r.Span), actual,
		"data_exfiltration_protection_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-158: Databricks workspace without customer-managed key
// ---------------------------------------------------------------------------

type databricksNoCMK struct{}

func (databricksNoCMK) ID() string { return "AEGIS-AZURE-158" }
func (databricksNoCMK) Title() string {
	return "Databricks workspace without customer-managed key"
}
func (databricksNoCMK) Description() string {
	return "azurerm_databricks_workspace without a customer_managed_key " +
		"block relies on Microsoft-managed keys for the managed services " +
		"encryption. Configure customer-managed keys for control over key " +
		"rotation and revocation."
}
func (databricksNoCMK) Severity() ir.Severity { return ir.SeverityMedium }

func (databricksNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_databricks_workspace"
}

func (s databricksNoCMK) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "customer_managed_key")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "customer_managed_key",
		evidenceSpan(span, r.Span), "absent (Microsoft-managed keys)",
		"customer_managed_key { ... }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-159: Databricks workspace with public network access
// ---------------------------------------------------------------------------

type databricksPublicNet struct{}

func (databricksPublicNet) ID() string { return "AEGIS-AZURE-159" }
func (databricksPublicNet) Title() string {
	return "Databricks workspace with public network access enabled"
}
func (databricksPublicNet) Description() string {
	return "azurerm_databricks_workspace with public_network_access_enabled " +
		"(the provider default) exposes the workspace to the internet. " +
		"Disable public network access and use VNet injection with private " +
		"endpoints."
}
func (databricksPublicNet) Severity() ir.Severity { return ir.SeverityMedium }

func (databricksPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_databricks_workspace"
}

func (s databricksPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_databricks_workspace")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-160: Event Grid topic with public network access
// ---------------------------------------------------------------------------

type eventGridPublicNet struct{}

func (eventGridPublicNet) ID() string { return "AEGIS-AZURE-160" }
func (eventGridPublicNet) Title() string {
	return "Event Grid topic with public network access enabled"
}
func (eventGridPublicNet) Description() string {
	return "azurerm_eventgrid_topic with public_network_access_enabled " +
		"(the provider default) accepts events over the public internet. " +
		"Disable public network access and use private endpoints."
}
func (eventGridPublicNet) Severity() ir.Severity { return ir.SeverityMedium }

func (eventGridPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_eventgrid_topic" ||
		resType == "azurerm_eventgrid_domain"
}

func (s eventGridPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", r.Type)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-161: Event Grid topic with local authentication enabled
// ---------------------------------------------------------------------------

type eventGridLocalAuth struct{}

func (eventGridLocalAuth) ID() string { return "AEGIS-AZURE-161" }
func (eventGridLocalAuth) Title() string {
	return "Event Grid topic with local authentication enabled"
}
func (eventGridLocalAuth) Description() string {
	return "azurerm_eventgrid_topic with local_auth_enabled (the provider " +
		"default) permits key-based publishing. Disable local auth and " +
		"publish with Microsoft Entra identities instead."
}
func (eventGridLocalAuth) Severity() ir.Severity { return ir.SeverityMedium }

func (eventGridLocalAuth) AppliesTo(resType string) bool {
	return resType == "azurerm_eventgrid_topic" ||
		resType == "azurerm_eventgrid_domain"
}

func (s eventGridLocalAuth) Check(r ir.Resource) []ir.Finding {
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
// AEGIS-AZURE-162: Machine Learning workspace with public network access
// ---------------------------------------------------------------------------

type mlWorkspacePublicNet struct{}

func (mlWorkspacePublicNet) ID() string { return "AEGIS-AZURE-162" }
func (mlWorkspacePublicNet) Title() string {
	return "Machine Learning workspace with public network access enabled"
}
func (mlWorkspacePublicNet) Description() string {
	return "azurerm_machine_learning_workspace with " +
		"public_network_access_enabled (the provider default) exposes " +
		"models, datasets and compute to the internet. Disable public " +
		"network access and use private endpoints."
}
func (mlWorkspacePublicNet) Severity() ir.Severity { return ir.SeverityHigh }

func (mlWorkspacePublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_machine_learning_workspace"
}

func (s mlWorkspacePublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_machine_learning_workspace")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-163: App Configuration without purge protection
// ---------------------------------------------------------------------------

type appConfigNoPurge struct{}

func (appConfigNoPurge) ID() string { return "AEGIS-AZURE-163" }
func (appConfigNoPurge) Title() string {
	return "App Configuration without purge protection"
}
func (appConfigNoPurge) Description() string {
	return "azurerm_app_configuration without purge_protection_enabled = " +
		"true can be permanently deleted immediately, losing feature flags " +
		"and secrets references. Enable purge protection."
}
func (appConfigNoPurge) Severity() ir.Severity { return ir.SeverityMedium }

func (appConfigNoPurge) AppliesTo(resType string) bool {
	return resType == "azurerm_app_configuration"
}

func (s appConfigNoPurge) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "purge_protection_enabled")
	if present && !known {
		return nil
	}
	if present && en {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{mkFinding(s, r, "purge_protection_enabled",
		evidenceSpan(span, r.Span), actual,
		"purge_protection_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-164: App Configuration with public network access
// ---------------------------------------------------------------------------

type appConfigPublicNet struct{}

func (appConfigPublicNet) ID() string { return "AEGIS-AZURE-164" }
func (appConfigPublicNet) Title() string {
	return "App Configuration with public network access enabled"
}
func (appConfigPublicNet) Description() string {
	return "azurerm_app_configuration with public_network_access_enabled " +
		"(the provider default) serves configuration and Key Vault " +
		"references over the public internet. Disable public network " +
		"access and use private endpoints."
}
func (appConfigPublicNet) Severity() ir.Severity { return ir.SeverityMedium }

func (appConfigPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_app_configuration"
}

func (s appConfigPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_app_configuration")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-165: Automation account with public network access
// ---------------------------------------------------------------------------

type automationPublicNet struct{}

func (automationPublicNet) ID() string { return "AEGIS-AZURE-165" }
func (automationPublicNet) Title() string {
	return "Automation account with public network access enabled"
}
func (automationPublicNet) Description() string {
	return "azurerm_automation_account with public_network_access_enabled " +
		"(the provider default) exposes runbooks, webhooks and DSC to the " +
		"internet. Disable public network access and use private endpoints."
}
func (automationPublicNet) Severity() ir.Severity { return ir.SeverityMedium }

func (automationPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_automation_account"
}

func (s automationPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_automation_account")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-166: Search service with public network access
// ---------------------------------------------------------------------------

type searchPublicNet struct{}

func (searchPublicNet) ID() string { return "AEGIS-AZURE-166" }
func (searchPublicNet) Title() string {
	return "Search service with public network access enabled"
}
func (searchPublicNet) Description() string {
	return "azurerm_search_service with public_network_access_enabled " +
		"(the provider default) exposes indexes and API keys to the " +
		"internet. Disable public network access and use private endpoints."
}
func (searchPublicNet) Severity() ir.Severity { return ir.SeverityMedium }

func (searchPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_search_service"
}

func (s searchPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_search_service")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-167: Cognitive account with public network access
// ---------------------------------------------------------------------------

type cognitivePublicNet struct{}

func (cognitivePublicNet) ID() string { return "AEGIS-AZURE-167" }
func (cognitivePublicNet) Title() string {
	return "Cognitive Services account with public network access enabled"
}
func (cognitivePublicNet) Description() string {
	return "azurerm_cognitive_account with public_network_access_enabled " +
		"(the provider default) exposes AI endpoints and keys to the " +
		"internet. Disable public network access and use private endpoints."
}
func (cognitivePublicNet) Severity() ir.Severity { return ir.SeverityMedium }

func (cognitivePublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_cognitive_account"
}

func (s cognitivePublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_cognitive_account")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-168: IoT Hub with public network access
// ---------------------------------------------------------------------------

type iotHubPublicNet struct{}

func (iotHubPublicNet) ID() string { return "AEGIS-AZURE-168" }
func (iotHubPublicNet) Title() string {
	return "IoT Hub with public network access enabled"
}
func (iotHubPublicNet) Description() string {
	return "azurerm_iothub with public_network_access_enabled (the provider " +
		"default) accepts device connections over the public internet. " +
		"Disable public network access where devices connect over private " +
		"networks."
}
func (iotHubPublicNet) Severity() ir.Severity { return ir.SeverityHigh }

func (iotHubPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_iothub"
}

func (s iotHubPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_iothub")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-169: PostgreSQL flexible server with public network access
// ---------------------------------------------------------------------------

type postgresFlexPublicNet struct{}

func (postgresFlexPublicNet) ID() string { return "AEGIS-AZURE-169" }
func (postgresFlexPublicNet) Title() string {
	return "PostgreSQL flexible server with public network access enabled"
}
func (postgresFlexPublicNet) Description() string {
	return "azurerm_postgresql_flexible_server with " +
		"public_network_access_enabled (the provider default) exposes the " +
		"database to the internet. Disable public network access and use " +
		"VNet integration or private endpoints."
}
func (postgresFlexPublicNet) Severity() ir.Severity { return ir.SeverityHigh }

func (postgresFlexPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_postgresql_flexible_server"
}

func (s postgresFlexPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_postgresql_flexible_server")
}
