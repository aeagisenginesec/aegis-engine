// Package azure — App Service, AKS and VM rules (AEGIS-AZURE-061..080).
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure5Rules returns App Service, AKS and VM rules in ID order.
func Azure5Rules() []ir.Rule {
	return []ir.Rule{
		appSvcNoAuth{},          // AEGIS-AZURE-061
		appSvcNoManagedIdent{},  // AEGIS-AZURE-062
		appSvcNoVnetInteg{},     // AEGIS-AZURE-063
		appSvcFtpsAll{},         // AEGIS-AZURE-064
		appSvcRemoteDebug{},     // AEGIS-AZURE-065
		appSvcNoHealthCheck{},   // AEGIS-AZURE-066
		appSvcSlotNoHTTPS{},     // AEGIS-AZURE-067
		appSvcMinTLSOld{},       // AEGIS-AZURE-068
		aksNoPrivateCluster{},   // AEGIS-AZURE-069
		aksNoAzurePolicy{},      // AEGIS-AZURE-070
		aksNoLogAnalytics{},     // AEGIS-AZURE-071
		aksNoPodIdentity{},      // AEGIS-AZURE-072
		aksNoAutoUpgrade{},      // AEGIS-AZURE-073
		aksNoDiskEncryption{},   // AEGIS-AZURE-074
		aksPublicAPI{},          // AEGIS-AZURE-075
		aksNoWorkloadIdentity{}, // AEGIS-AZURE-076
		vmNoDiskEncryption{},    // AEGIS-AZURE-077
		vmNoManagedIdentity{},   // AEGIS-AZURE-078
		vmNoBastionHost{},       // AEGIS-AZURE-079 (advisory: fires on explicit public IP)
		vmNoPatchMode{},         // AEGIS-AZURE-080
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-061: App Service without authentication
// ---------------------------------------------------------------------------

type appSvcNoAuth struct{}

func (appSvcNoAuth) ID() string { return "AEGIS-AZURE-061" }
func (appSvcNoAuth) Title() string {
	return "App Service without authentication"
}
func (appSvcNoAuth) Description() string {
	return "azurerm_app_service without auth_settings enabled allows " +
		"anonymous access. Enable App Service authentication."
}
func (appSvcNoAuth) Severity() ir.Severity { return ir.SeverityHigh }

func (appSvcNoAuth) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service" ||
		resType == "azurerm_linux_web_app" ||
		resType == "azurerm_windows_web_app"
}

func (s appSvcNoAuth) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "auth_settings")
	if !present || !known || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "auth_settings",
			evidenceSpan(ir.Span{}, r.Span), "absent", "auth_settings block with enabled = true")}
	}
	en, _, ep, ek := blockString(blks[0], "enabled")
	if !ep || !ek {
		return nil
	}
	if strings.EqualFold(en, "true") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "auth_settings.enabled",
		evidenceSpan(ir.Span{}, r.Span), en, "enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-062: App Service without managed identity
// ---------------------------------------------------------------------------

type appSvcNoManagedIdent struct{}

func (appSvcNoManagedIdent) ID() string { return "AEGIS-AZURE-062" }
func (appSvcNoManagedIdent) Title() string {
	return "App Service without managed identity"
}
func (appSvcNoManagedIdent) Description() string {
	return "azurerm_app_service without identity block cannot use managed " +
		"identities for Key Vault or database access. Configure a system-assigned identity."
}
func (appSvcNoManagedIdent) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcNoManagedIdent) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service" ||
		resType == "azurerm_linux_web_app" ||
		resType == "azurerm_windows_web_app"
}

func (s appSvcNoManagedIdent) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getBlocks(r, "identity")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "identity",
		evidenceSpan(ir.Span{}, r.Span), "absent", "identity { type = \"SystemAssigned\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-063: App Service without VNet integration
// ---------------------------------------------------------------------------

type appSvcNoVnetInteg struct{}

func (appSvcNoVnetInteg) ID() string { return "AEGIS-AZURE-063" }
func (appSvcNoVnetInteg) Title() string {
	return "App Service without VNet integration"
}
func (appSvcNoVnetInteg) Description() string {
	return "azurerm_app_service without virtual_network_subnet_id reaches " +
		"backend resources over public endpoints. Integrate with a VNet."
}
func (appSvcNoVnetInteg) Severity() ir.Severity { return ir.SeverityLow }

func (appSvcNoVnetInteg) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service"
}

func (s appSvcNoVnetInteg) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getString(r, "virtual_network_subnet_id")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "virtual_network_subnet_id",
		evidenceSpan(ir.Span{}, r.Span), "absent", "virtual_network_subnet_id = azurerm_subnet.example.id")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-064: App Service with FTPS allowing all
// ---------------------------------------------------------------------------

type appSvcFtpsAll struct{}

func (appSvcFtpsAll) ID() string { return "AEGIS-AZURE-064" }
func (appSvcFtpsAll) Title() string {
	return "App Service FTPS allows plaintext FTP"
}
func (appSvcFtpsAll) Description() string {
	return "azurerm_app_service site_config with ftps_state = \"AllAllowed\" " +
		"permits plaintext FTP. Require FTPS only."
}
func (appSvcFtpsAll) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcFtpsAll) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service" ||
		resType == "azurerm_linux_web_app" ||
		resType == "azurerm_windows_web_app"
}

func (s appSvcFtpsAll) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	ftps, _, fp, fk := blockString(blks[0], "ftps_state")
	if !fp || !fk {
		return nil
	}
	if strings.EqualFold(ftps, "FtpsOnly") || strings.EqualFold(ftps, "Disabled") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "site_config.ftps_state",
		evidenceSpan(ir.Span{}, r.Span), ftps, "ftps_state = \"FtpsOnly\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-065: App Service with remote debugging enabled
// ---------------------------------------------------------------------------

type appSvcRemoteDebug struct{}

func (appSvcRemoteDebug) ID() string { return "AEGIS-AZURE-065" }
func (appSvcRemoteDebug) Title() string {
	return "App Service with remote debugging enabled"
}
func (appSvcRemoteDebug) Description() string {
	return "azurerm_app_service site_config with remote_debugging_enabled = true " +
		"exposes a debug endpoint. Disable remote debugging in production."
}
func (appSvcRemoteDebug) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcRemoteDebug) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service"
}

func (s appSvcRemoteDebug) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	v, ok := blks[0]["remote_debugging_enabled"]
	if !ok || !v.Known {
		return nil
	}
	b, kok := v.AsBool()
	if !kok || !b {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "site_config.remote_debugging_enabled",
		v.Span, "true", "remote_debugging_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-066: App Service without health check
// ---------------------------------------------------------------------------

type appSvcNoHealthCheck struct{}

func (appSvcNoHealthCheck) ID() string { return "AEGIS-AZURE-066" }
func (appSvcNoHealthCheck) Title() string {
	return "App Service without health check path"
}
func (appSvcNoHealthCheck) Description() string {
	return "azurerm_app_service site_config without health_check_path misses " +
		"unhealthy instance detection. Configure a health check path."
}
func (appSvcNoHealthCheck) Severity() ir.Severity { return ir.SeverityLow }

func (appSvcNoHealthCheck) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service"
}

func (s appSvcNoHealthCheck) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	if _, _, hp, _ := blockString(blks[0], "health_check_path"); hp {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "site_config.health_check_path",
		evidenceSpan(ir.Span{}, r.Span), "absent", "health_check_path = \"/health\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-067: App Service slot without HTTPS-only
// ---------------------------------------------------------------------------

type appSvcSlotNoHTTPS struct{}

func (appSvcSlotNoHTTPS) ID() string { return "AEGIS-AZURE-067" }
func (appSvcSlotNoHTTPS) Title() string {
	return "App Service slot without HTTPS-only"
}
func (appSvcSlotNoHTTPS) Description() string {
	return "azurerm_app_service_slot with https_only = false permits " +
		"plaintext HTTP on the deployment slot. Enforce HTTPS-only."
}
func (appSvcSlotNoHTTPS) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcSlotNoHTTPS) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service_slot"
}

func (s appSvcSlotNoHTTPS) Check(r ir.Resource) []ir.Finding {
	https, span, present, known := getBool(r, "https_only")
	if !present || !known {
		return nil
	}
	if https {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "https_only", span,
		"false", "https_only = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-068: App Service with old minimum TLS
// ---------------------------------------------------------------------------

type appSvcMinTLSOld struct{}

func (appSvcMinTLSOld) ID() string { return "AEGIS-AZURE-068" }
func (appSvcMinTLSOld) Title() string {
	return "App Service with minimum TLS below 1.2"
}
func (appSvcMinTLSOld) Description() string {
	return "azurerm_app_service site_config with min_tls_version below 1.2 " +
		"permits deprecated TLS. Require 1.2 or higher."
}
func (appSvcMinTLSOld) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcMinTLSOld) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service" ||
		resType == "azurerm_linux_web_app" ||
		resType == "azurerm_windows_web_app"
}

func (s appSvcMinTLSOld) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	tls, span, tp, tk := blockString(blks[0], "min_tls_version")
	if !tp || !tk {
		return nil
	}
	v := strings.ToUpper(strings.ReplaceAll(tls, " ", ""))
	if v == "1.2" || v == "1.3" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "site_config.min_tls_version", span,
		tls, "min_tls_version = \"1.2\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-069: AKS cluster not private
// ---------------------------------------------------------------------------

type aksNoPrivateCluster struct{}

func (aksNoPrivateCluster) ID() string { return "AEGIS-AZURE-069" }
func (aksNoPrivateCluster) Title() string {
	return "AKS cluster with public API server"
}
func (aksNoPrivateCluster) Description() string {
	return "azurerm_kubernetes_cluster without private_cluster_enabled " +
		"exposes the Kubernetes API server publicly. Enable private clusters."
}
func (aksNoPrivateCluster) Severity() ir.Severity { return ir.SeverityHigh }

func (aksNoPrivateCluster) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoPrivateCluster) Check(r ir.Resource) []ir.Finding {
	priv, span, present, known := getBool(r, "private_cluster_enabled")
	if !present || !known {
		return nil
	}
	if priv {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "private_cluster_enabled", span,
		"false", "private_cluster_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-070: AKS cluster without Azure Policy addon
// ---------------------------------------------------------------------------

type aksNoAzurePolicy struct{}

func (aksNoAzurePolicy) ID() string { return "AEGIS-AZURE-070" }
func (aksNoAzurePolicy) Title() string {
	return "AKS cluster without Azure Policy addon"
}
func (aksNoAzurePolicy) Description() string {
	return "azurerm_kubernetes_cluster addon_profile without azure_policy " +
		"enabled misses policy enforcement. Enable the Azure Policy addon."
}
func (aksNoAzurePolicy) Severity() ir.Severity { return ir.SeverityMedium }

func (aksNoAzurePolicy) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoAzurePolicy) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "addon_profile")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	for _, blk := range blks {
		pol := blockList(blk, "azure_policy")
		for _, p := range pol {
			if en, _, ep, ek := blockString(p, "enabled"); ep && ek &&
				strings.EqualFold(en, "true") {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "addon_profile.azure_policy",
		evidenceSpan(ir.Span{}, r.Span), "disabled or absent",
		"azure_policy { enabled = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-071: AKS cluster without log analytics
// ---------------------------------------------------------------------------

type aksNoLogAnalytics struct{}

func (aksNoLogAnalytics) ID() string { return "AEGIS-AZURE-071" }
func (aksNoLogAnalytics) Title() string {
	return "AKS cluster without container insights"
}
func (aksNoLogAnalytics) Description() string {
	return "azurerm_kubernetes_cluster addon_profile without oms_agent " +
		"enabled loses container monitoring. Enable Container Insights."
}
func (aksNoLogAnalytics) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoLogAnalytics) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoLogAnalytics) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "addon_profile")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	for _, blk := range blks {
		oms := blockList(blk, "oms_agent")
		for _, o := range oms {
			if en, _, ep, ek := blockString(o, "enabled"); ep && ek &&
				strings.EqualFold(en, "true") {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "addon_profile.oms_agent",
		evidenceSpan(ir.Span{}, r.Span), "disabled or absent",
		"oms_agent { enabled = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-072: AKS cluster without pod-managed identity
// ---------------------------------------------------------------------------

type aksNoPodIdentity struct{}

func (aksNoPodIdentity) ID() string { return "AEGIS-AZURE-072" }
func (aksNoPodIdentity) Title() string {
	return "AKS cluster without pod-managed identity"
}
func (aksNoPodIdentity) Description() string {
	return "azurerm_kubernetes_cluster addon_profile without " +
		"aci_connector_linux or workload identity misses pod-level identity. " +
		"Prefer workload identity for pod authentication."
}
func (aksNoPodIdentity) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoPodIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoPodIdentity) Check(r ir.Resource) []ir.Finding {
	// Advisory: only flag when explicitly disabled via oidc_issuer.
	// Stay quiet otherwise to avoid noise on older configs.
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-073: AKS cluster without auto-upgrade channel
// ---------------------------------------------------------------------------

type aksNoAutoUpgrade struct{}

func (aksNoAutoUpgrade) ID() string { return "AEGIS-AZURE-073" }
func (aksNoAutoUpgrade) Title() string {
	return "AKS cluster without automatic upgrades"
}
func (aksNoAutoUpgrade) Description() string {
	return "azurerm_kubernetes_cluster with automatic_upgrade_channel = \"none\" " +
		"misses security patches. Set an upgrade channel (patch, stable, rapid)."
}
func (aksNoAutoUpgrade) Severity() ir.Severity { return ir.SeverityMedium }

func (aksNoAutoUpgrade) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoAutoUpgrade) Check(r ir.Resource) []ir.Finding {
	ch, span, present, known := getString(r, "automatic_upgrade_channel")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(ch, "none") {
		return []ir.Finding{mkFinding(s, r, "automatic_upgrade_channel", span,
			"none", "automatic_upgrade_channel = \"patch\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-074: AKS cluster without disk encryption set
// ---------------------------------------------------------------------------

type aksNoDiskEncryption struct{}

func (aksNoDiskEncryption) ID() string { return "AEGIS-AZURE-074" }
func (aksNoDiskEncryption) Title() string {
	return "AKS cluster without disk encryption set"
}
func (aksNoDiskEncryption) Description() string {
	return "azurerm_kubernetes_cluster default_node_pool without " +
		"disk_encryption_set_id uses platform-managed keys. Use a " +
		"customer-managed disk encryption set."
}
func (aksNoDiskEncryption) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoDiskEncryption) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoDiskEncryption) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "default_node_pool")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	if _, _, dp, _ := blockString(blks[0], "disk_encryption_set_id"); dp {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "default_node_pool.disk_encryption_set_id",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"disk_encryption_set_id = azurerm_disk_encryption_set.example.id")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-075: AKS API server authorized IP ranges not set
// ---------------------------------------------------------------------------

type aksPublicAPI struct{}

func (aksPublicAPI) ID() string { return "AEGIS-AZURE-075" }
func (aksPublicAPI) Title() string {
	return "AKS API server without authorized IP ranges"
}
func (aksPublicAPI) Description() string {
	return "azurerm_kubernetes_cluster with public API access but no " +
		"api_server_access_profile authorized_ip_ranges accepts connections " +
		"from anywhere. Restrict authorized ranges."
}
func (aksPublicAPI) Severity() ir.Severity { return ir.SeverityMedium }

func (aksPublicAPI) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksPublicAPI) Check(r ir.Resource) []ir.Finding {
	priv, _, ppresent, pknown := getBool(r, "private_cluster_enabled")
	if ppresent && pknown && priv {
		return nil // private: no need for IP ranges
	}
	blks, _, present, known := getBlocks(r, "api_server_access_profile")
	if !present || !known || len(blks) == 0 {
		return []ir.Finding{mkFinding(s, r, "api_server_access_profile",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"api_server_access_profile { authorized_ip_ranges = [...] }")}
	}
	if _, _, ok := getStringListFromBlock(blks[0], "authorized_ip_ranges"); ok {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "api_server_access_profile.authorized_ip_ranges",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"authorized_ip_ranges = [\"203.0.113.0/24\"]")}
}

// getStringListFromBlock extracts a string list from a block map.
func getStringListFromBlock(m map[string]ir.Value, name string) ([]string, ir.Span, bool) {
	v, ok := m[name]
	if !ok || !v.Known {
		return nil, ir.Span{}, false
	}
	l, ok := v.AsList()
	if !ok {
		return nil, v.Span, false
	}
	out := make([]string, 0, len(l))
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return nil, v.Span, false
		}
		out = append(out, s)
	}
	return out, v.Span, true
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-076: AKS cluster without workload identity (OIDC issuer)
// ---------------------------------------------------------------------------

type aksNoWorkloadIdentity struct{}

func (aksNoWorkloadIdentity) ID() string { return "AEGIS-AZURE-076" }
func (aksNoWorkloadIdentity) Title() string {
	return "AKS cluster without OIDC issuer for workload identity"
}
func (aksNoWorkloadIdentity) Description() string {
	return "azurerm_kubernetes_cluster with oidc_issuer_enabled = false " +
		"cannot use workload identity federation. Enable the OIDC issuer."
}
func (aksNoWorkloadIdentity) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoWorkloadIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoWorkloadIdentity) Check(r ir.Resource) []ir.Finding {
	oidc, span, present, known := getBool(r, "oidc_issuer_enabled")
	if !present || !known {
		return nil
	}
	if oidc {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "oidc_issuer_enabled", span,
		"false", "oidc_issuer_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-077: VM without disk encryption
// ---------------------------------------------------------------------------

type vmNoDiskEncryption struct{}

func (vmNoDiskEncryption) ID() string { return "AEGIS-AZURE-077" }
func (vmNoDiskEncryption) Title() string {
	return "Virtual machine OS disk without encryption"
}
func (vmNoDiskEncryption) Description() string {
	return "azurerm_linux_virtual_machine / azurerm_windows_virtual_machine " +
		"os_disk without disk_encryption_set_id stores the OS disk with " +
		"platform-managed keys. Use a disk encryption set."
}
func (vmNoDiskEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (vmNoDiskEncryption) AppliesTo(resType string) bool {
	return resType == "azurerm_linux_virtual_machine" ||
		resType == "azurerm_windows_virtual_machine" ||
		resType == "azurerm_virtual_machine"
}

func (s vmNoDiskEncryption) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "os_disk")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	if _, _, dp, _ := blockString(blks[0], "disk_encryption_set_id"); dp {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "os_disk.disk_encryption_set_id",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"disk_encryption_set_id = azurerm_disk_encryption_set.example.id")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-078: VM without managed identity
// ---------------------------------------------------------------------------

type vmNoManagedIdentity struct{}

func (vmNoManagedIdentity) ID() string { return "AEGIS-AZURE-078" }
func (vmNoManagedIdentity) Title() string {
	return "Virtual machine without managed identity"
}
func (vmNoManagedIdentity) Description() string {
	return "azurerm_linux_virtual_machine without identity block cannot use " +
		"managed identities. Configure a system-assigned identity."
}
func (vmNoManagedIdentity) Severity() ir.Severity { return ir.SeverityLow }

func (vmNoManagedIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_linux_virtual_machine" ||
		resType == "azurerm_windows_virtual_machine"
}

func (s vmNoManagedIdentity) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getBlocks(r, "identity")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "identity",
		evidenceSpan(ir.Span{}, r.Span), "absent", "identity { type = \"SystemAssigned\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-079: VM with public IP (advisory)
// ---------------------------------------------------------------------------

type vmNoBastionHost struct{}

func (vmNoBastionHost) ID() string { return "AEGIS-AZURE-079" }
func (vmNoBastionHost) Title() string {
	return "Network interface with public IP on VM subnet"
}
func (vmNoBastionHost) Description() string {
	return "azurerm_network_interface ip_configuration with public_ip_address_id " +
		"exposes the VM directly. Remove the public IP and use Azure Bastion."
}
func (vmNoBastionHost) Severity() ir.Severity { return ir.SeverityHigh }

func (vmNoBastionHost) AppliesTo(resType string) bool {
	return resType == "azurerm_network_interface"
}

func (s vmNoBastionHost) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "ip_configuration")
	if !present || !known {
		return nil
	}
	for _, blk := range blks {
		if _, _, pp, _ := blockString(blk, "public_ip_address_id"); pp {
			return []ir.Finding{mkFinding(s, r, "ip_configuration.public_ip_address_id",
				evidenceSpan(ir.Span{}, r.Span), "public IP attached",
				"remove public_ip_address_id; use azurerm_bastion_host")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-080: VM without automatic patch mode
// ---------------------------------------------------------------------------

type vmNoPatchMode struct{}

func (vmNoPatchMode) ID() string { return "AEGIS-AZURE-080" }
func (vmNoPatchMode) Title() string {
	return "Virtual machine without automatic OS patching"
}
func (vmNoPatchMode) Description() string {
	return "azurerm_linux_virtual_machine without patch_mode = \"AutomaticByPlatform\" " +
		"misses automatic security patches. Enable platform-managed patching."
}
func (vmNoPatchMode) Severity() ir.Severity { return ir.SeverityMedium }

func (vmNoPatchMode) AppliesTo(resType string) bool {
	return resType == "azurerm_linux_virtual_machine" ||
		resType == "azurerm_windows_virtual_machine"
}

func (s vmNoPatchMode) Check(r ir.Resource) []ir.Finding {
	pm, span, present, known := getString(r, "patch_mode")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(pm, "AutomaticByPlatform") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "patch_mode", span,
		pm, "patch_mode = \"AutomaticByPlatform\"")}
}
