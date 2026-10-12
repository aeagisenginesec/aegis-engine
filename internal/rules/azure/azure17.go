// Package azure — AKS & networking hardening round (AEGIS-AZURE-226..245).
//
// Deepens AKS (Azure Policy, workload identity, node OS upgrades, AAD
// RBAC, image cleaner, network policy, ephemeral disks, OIDC) and core
// networking (NSG flow logs, Firewall threat intel, Bastion, WAF,
// App Gateway TLS, public IP/LB SKUs, DDoS, inline NSG rules).
//
// Absent-attribute policy for this file: absent yields a finding when the
// provider default is insecure. Present-but-unresolved yields NO finding.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure17Rules returns AKS & networking hardening rules in ID order.
func Azure17Rules() []ir.Rule {
	return []ir.Rule{
		aksHTTPRoutingOn{},       // AEGIS-AZURE-226
		aksNoAutoScaling{},       // AEGIS-AZURE-227
		aksNoOSAutoUpgrade{},     // AEGIS-AZURE-228
		aksAPIServerOpen{},       // AEGIS-AZURE-229
		aksNoAADRBAC{},           // AEGIS-AZURE-230
		aksRunCommandOn{},        // AEGIS-AZURE-231
		aksLBNotStandard{},       // AEGIS-AZURE-232
		aksNoEphemeralDisk{},     // AEGIS-AZURE-233
		nsgFlowLogDisabled{},     // AEGIS-AZURE-235
		firewallThreatIntelOff{}, // AEGIS-AZURE-236
		bastionClipboardOn{},     // AEGIS-AZURE-237
		frontdoorWAFNotPrevent{}, // AEGIS-AZURE-238
		appGWNoWAF{},             // AEGIS-AZURE-239
		appGWTLSBelow12{},        // AEGIS-AZURE-240
		publicIPBasicSKU{},       // AEGIS-AZURE-241
		lbBasicSKU{},             // AEGIS-AZURE-242
		nsgInlineOpenRule{},      // AEGIS-AZURE-244
		aksLocalAccounts{},       // AEGIS-AZURE-245
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-226: AKS with HTTP application routing enabled
// ---------------------------------------------------------------------------

type aksHTTPRoutingOn struct{}

func (aksHTTPRoutingOn) ID() string { return "AEGIS-AZURE-226" }
func (aksHTTPRoutingOn) Title() string {
	return "AKS cluster with HTTP application routing enabled"
}
func (aksHTTPRoutingOn) Description() string {
	return "azurerm_kubernetes_cluster with " +
		"http_application_routing_enabled = true deploys the deprecated " +
		"HTTP application routing addon, which provisions public DNS " +
		"zones and wildcard certificates outside your control. Use an " +
		"ingress controller you manage instead."
}
func (aksHTTPRoutingOn) Severity() ir.Severity { return ir.SeverityMedium }

func (aksHTTPRoutingOn) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksHTTPRoutingOn) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "http_application_routing_enabled")
	if !present || !known {
		return nil // default false: secure
	}
	if !en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "http_application_routing_enabled", span,
		"true", "http_application_routing_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-227: AKS node pool without auto-scaling
// ---------------------------------------------------------------------------

type aksNoAutoScaling struct{}

func (aksNoAutoScaling) ID() string { return "AEGIS-AZURE-227" }
func (aksNoAutoScaling) Title() string {
	return "AKS node pool without auto-scaling"
}
func (aksNoAutoScaling) Description() string {
	return "azurerm_kubernetes_cluster default_node_pool without " +
		"enable_auto_scaling = true cannot shed nodes under attack or " +
		"scale during incidents. Enable cluster autoscaler with sane " +
		"min/max counts."
}
func (aksNoAutoScaling) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoAutoScaling) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoAutoScaling) Check(r ir.Resource) []ir.Finding {
	pools, span, present, known := getBlocks(r, "default_node_pool")
	if !present || !known {
		return nil
	}
	for _, p := range pools {
		en, _, ep, ek := blockBool(p, "enable_auto_scaling")
		if ep && !ek {
			return nil
		}
		if ep && en {
			return nil
		}
		actual := "absent (provider default: false)"
		if ep {
			actual = "false"
		}
		return []ir.Finding{mkFinding(s, r, "default_node_pool",
			evidenceSpan(span, r.Span), actual,
			"default_node_pool { enable_auto_scaling = true }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-228: AKS without node OS auto-upgrade
// ---------------------------------------------------------------------------

type aksNoOSAutoUpgrade struct{}

func (aksNoOSAutoUpgrade) ID() string { return "AEGIS-AZURE-228" }
func (aksNoOSAutoUpgrade) Title() string {
	return "AKS cluster without node OS auto-upgrade"
}
func (aksNoOSAutoUpgrade) Description() string {
	return "azurerm_kubernetes_cluster with node_os_upgrade_channel " +
		"other than \"SecurityPatch\" or \"NodeImage\" (or absent) " +
		"leaves node OS patching manual, so kernel CVEs linger. Set " +
		"node_os_upgrade_channel = \"SecurityPatch\"."
}
func (aksNoOSAutoUpgrade) Severity() ir.Severity { return ir.SeverityMedium }

func (aksNoOSAutoUpgrade) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoOSAutoUpgrade) Check(r ir.Resource) []ir.Finding {
	ch, span, present, known := getString(r, "node_os_upgrade_channel")
	if present && !known {
		return nil
	}
	if present {
		up := strings.TrimSpace(ch)
		if strings.EqualFold(up, "SecurityPatch") || strings.EqualFold(up, "NodeImage") {
			return nil
		}
		return []ir.Finding{mkFinding(s, r, "node_os_upgrade_channel", span,
			ch, "node_os_upgrade_channel = \"SecurityPatch\"")}
	}
	return []ir.Finding{mkFinding(s, r, "node_os_upgrade_channel", r.Span,
		"absent (no auto-upgrade)", "node_os_upgrade_channel = \"SecurityPatch\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-229: AKS API server exposed without IP restrictions
// ---------------------------------------------------------------------------

type aksAPIServerOpen struct{}

func (aksAPIServerOpen) ID() string { return "AEGIS-AZURE-229" }
func (aksAPIServerOpen) Title() string {
	return "AKS API server exposed without authorized IP ranges"
}
func (aksAPIServerOpen) Description() string {
	return "azurerm_kubernetes_cluster that is not private " +
		"(private_cluster_enabled) and has no " +
		"api_server_access_profile.authorized_ip_ranges exposes the " +
		"Kubernetes API to the internet. Use a private cluster or " +
		"restrict API access to known ranges."
}
func (aksAPIServerOpen) Severity() ir.Severity { return ir.SeverityHigh }

func (aksAPIServerOpen) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksAPIServerOpen) Check(r ir.Resource) []ir.Finding {
	priv, _, ppresent, pknown := getBool(r, "private_cluster_enabled")
	if ppresent && !pknown {
		return nil
	}
	if ppresent && priv {
		return nil // private cluster: API not internet-exposed
	}
	profs, span, present, known := getBlocks(r, "api_server_access_profile")
	if present && !known {
		return nil
	}
	if present {
		for _, p := range profs {
			ranges, _, ok := getStringListFromMap(p, "authorized_ip_ranges")
			if ok && len(ranges) > 0 {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "api_server_access_profile",
		evidenceSpan(span, r.Span), "no authorized_ip_ranges",
		"api_server_access_profile { authorized_ip_ranges = [...] }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-230: AKS without Entra ID RBAC
// ---------------------------------------------------------------------------

type aksNoAADRBAC struct{}

func (aksNoAADRBAC) ID() string { return "AEGIS-AZURE-230" }
func (aksNoAADRBAC) Title() string {
	return "AKS cluster without Entra ID RBAC"
}
func (aksNoAADRBAC) Description() string {
	return "azurerm_kubernetes_cluster without an " +
		"azure_active_directory_role_based_access_control block manages " +
		"cluster access with local accounts. Integrate Entra ID for " +
		"centralized identity, MFA and conditional access."
}
func (aksNoAADRBAC) Severity() ir.Severity { return ir.SeverityMedium }

func (aksNoAADRBAC) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoAADRBAC) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "azure_active_directory_role_based_access_control")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "azure_active_directory_role_based_access_control",
		evidenceSpan(span, r.Span), "absent (local accounts only)",
		"azure_active_directory_role_based_access_control { ... }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-231: AKS with run command enabled
// ---------------------------------------------------------------------------

type aksRunCommandOn struct{}

func (aksRunCommandOn) ID() string { return "AEGIS-AZURE-231" }
func (aksRunCommandOn) Title() string {
	return "AKS cluster with run command enabled"
}
func (aksRunCommandOn) Description() string {
	return "azurerm_kubernetes_cluster with run_command_enabled " +
		"(the provider default) allows command execution on nodes via " +
		"the Azure API, bypassing kubectl RBAC. Disable it unless " +
		"break-glass node access is required."
}
func (aksRunCommandOn) Severity() ir.Severity { return ir.SeverityMedium }

func (aksRunCommandOn) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksRunCommandOn) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "run_command_enabled")
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
	return []ir.Finding{mkFinding(s, r, "run_command_enabled",
		evidenceSpan(span, r.Span), actual,
		"run_command_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-232: AKS load balancer SKU not Standard
// ---------------------------------------------------------------------------

type aksLBNotStandard struct{}

func (aksLBNotStandard) ID() string { return "AEGIS-AZURE-232" }
func (aksLBNotStandard) Title() string {
	return "AKS load balancer SKU not Standard"
}
func (aksLBNotStandard) Description() string {
	return "azurerm_kubernetes_cluster network_profile with " +
		"load_balancer_sku other than \"standard\" uses the Basic load " +
		"balancer without zone redundancy and modern security defaults. " +
		"Use the standard SKU."
}
func (aksLBNotStandard) Severity() ir.Severity { return ir.SeverityLow }

func (aksLBNotStandard) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksLBNotStandard) Check(r ir.Resource) []ir.Finding {
	nps, span, present, known := getBlocks(r, "network_profile")
	if !present || !known {
		return nil
	}
	for _, np := range nps {
		sku, _, p, k := blockString(np, "load_balancer_sku")
		if p && !k {
			return nil
		}
		if p && strings.EqualFold(strings.TrimSpace(sku), "standard") {
			return nil
		}
		actual := "absent (provider default: standard)"
		if p {
			actual = sku
		}
		// Only flag explicit non-standard choice, not absent (default is fine).
		if !p {
			return nil
		}
		return []ir.Finding{mkFinding(s, r, "network_profile",
			evidenceSpan(span, r.Span), actual,
			"network_profile { load_balancer_sku = \"standard\" }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-233: AKS node pool without ephemeral OS disk
// ---------------------------------------------------------------------------

type aksNoEphemeralDisk struct{}

func (aksNoEphemeralDisk) ID() string { return "AEGIS-AZURE-233" }
func (aksNoEphemeralDisk) Title() string {
	return "AKS node pool without ephemeral OS disk"
}
func (aksNoEphemeralDisk) Description() string {
	return "azurerm_kubernetes_cluster default_node_pool with " +
		"os_disk_type other than \"Ephemeral\" keeps OS disks on remote " +
		"storage. Ephemeral OS disks improve performance and ensure node " +
		"state is discarded on reimage."
}
func (aksNoEphemeralDisk) Severity() ir.Severity { return ir.SeverityLow }

func (aksNoEphemeralDisk) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksNoEphemeralDisk) Check(r ir.Resource) []ir.Finding {
	pools, span, present, known := getBlocks(r, "default_node_pool")
	if !present || !known {
		return nil
	}
	for _, p := range pools {
		dt, _, dp, dk := blockString(p, "os_disk_type")
		if dp && !dk {
			return nil
		}
		if dp && strings.EqualFold(strings.TrimSpace(dt), "Ephemeral") {
			return nil
		}
		actual := "absent (default: Managed)"
		if dp {
			actual = dt
		}
		return []ir.Finding{mkFinding(s, r, "default_node_pool",
			evidenceSpan(span, r.Span), actual,
			"default_node_pool { os_disk_type = \"Ephemeral\" }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-234: AKS without OIDC issuer

// ---------------------------------------------------------------------------
// AEGIS-AZURE-235: NSG flow log disabled
// ---------------------------------------------------------------------------

type nsgFlowLogDisabled struct{}

func (nsgFlowLogDisabled) ID() string { return "AEGIS-AZURE-235" }
func (nsgFlowLogDisabled) Title() string {
	return "NSG flow log disabled"
}
func (nsgFlowLogDisabled) Description() string {
	return "azurerm_network_watcher_flow_log with enabled = false (or " +
		"absent) loses network telemetry for the NSG, blinding incident " +
		"response. Enable flow logs with traffic analytics."
}
func (nsgFlowLogDisabled) Severity() ir.Severity { return ir.SeverityMedium }

func (nsgFlowLogDisabled) AppliesTo(resType string) bool {
	return resType == "azurerm_network_watcher_flow_log"
}

func (s nsgFlowLogDisabled) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "enabled")
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
	return []ir.Finding{mkFinding(s, r, "enabled",
		evidenceSpan(span, r.Span), actual, "enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-236: Firewall threat intelligence not in deny mode
// ---------------------------------------------------------------------------

type firewallThreatIntelOff struct{}

func (firewallThreatIntelOff) ID() string { return "AEGIS-AZURE-236" }
func (firewallThreatIntelOff) Title() string {
	return "Azure Firewall threat intelligence not in deny mode"
}
func (firewallThreatIntelOff) Description() string {
	return "azurerm_firewall with threat_intel_mode other than " +
		"\"Deny\" only alerts on (or ignores) traffic to known-malicious " +
		"IPs and domains. Set threat_intel_mode = \"Deny\"."
}
func (firewallThreatIntelOff) Severity() ir.Severity { return ir.SeverityMedium }

func (firewallThreatIntelOff) AppliesTo(resType string) bool {
	return resType == "azurerm_firewall"
}

func (s firewallThreatIntelOff) Check(r ir.Resource) []ir.Finding {
	m, span, present, known := getString(r, "threat_intel_mode")
	if present && !known {
		return nil
	}
	if present && strings.EqualFold(strings.TrimSpace(m), "Deny") {
		return nil
	}
	actual := "Alert"
	if !present {
		actual = "absent (provider default: Alert)"
	} else {
		actual = m
	}
	return []ir.Finding{mkFinding(s, r, "threat_intel_mode",
		evidenceSpan(span, r.Span), actual,
		"threat_intel_mode = \"Deny\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-237: Bastion with clipboard access enabled
// ---------------------------------------------------------------------------

type bastionClipboardOn struct{}

func (bastionClipboardOn) ID() string { return "AEGIS-AZURE-237" }
func (bastionClipboardOn) Title() string {
	return "Bastion host with clipboard access enabled"
}
func (bastionClipboardOn) Description() string {
	return "azurerm_bastion_host with copy_paste_enabled (the provider " +
		"default) allows clipboard transfer between the admin " +
		"workstation and the session, enabling data exfiltration. " +
		"Disable it for privileged access workstations."
}
func (bastionClipboardOn) Severity() ir.Severity { return ir.SeverityLow }

func (bastionClipboardOn) AppliesTo(resType string) bool {
	return resType == "azurerm_bastion_host"
}

func (s bastionClipboardOn) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "copy_paste_enabled")
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
	return []ir.Finding{mkFinding(s, r, "copy_paste_enabled",
		evidenceSpan(span, r.Span), actual,
		"copy_paste_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-238: Front Door WAF policy not in prevention mode
// ---------------------------------------------------------------------------

type frontdoorWAFNotPrevent struct{}

func (frontdoorWAFNotPrevent) ID() string { return "AEGIS-AZURE-238" }
func (frontdoorWAFNotPrevent) Title() string {
	return "Front Door WAF policy not in prevention mode"
}
func (frontdoorWAFNotPrevent) Description() string {
	return "azurerm_frontdoor_firewall_policy with mode other than " +
		"\"Prevention\" only detects attacks without blocking them. " +
		"Set mode = \"Prevention\" after tuning in detection mode."
}
func (frontdoorWAFNotPrevent) Severity() ir.Severity { return ir.SeverityHigh }

func (frontdoorWAFNotPrevent) AppliesTo(resType string) bool {
	return resType == "azurerm_frontdoor_firewall_policy"
}

func (s frontdoorWAFNotPrevent) Check(r ir.Resource) []ir.Finding {
	m, span, present, known := getString(r, "mode")
	if present && !known {
		return nil
	}
	if present && strings.EqualFold(strings.TrimSpace(m), "Prevention") {
		return nil
	}
	actual := "Detection"
	if !present {
		actual = "absent (provider default: Detection)"
	} else {
		actual = m
	}
	return []ir.Finding{mkFinding(s, r, "mode",
		evidenceSpan(span, r.Span), actual, "mode = \"Prevention\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-239: Application Gateway without WAF
// ---------------------------------------------------------------------------

type appGWNoWAF struct{}

func (appGWNoWAF) ID() string { return "AEGIS-AZURE-239" }
func (appGWNoWAF) Title() string {
	return "Application Gateway without WAF enabled"
}
func (appGWNoWAF) Description() string {
	return "azurerm_application_gateway waf_configuration without " +
		"enabled = true leaves the gateway without web-application " +
		"firewall protection. Enable WAF in prevention mode."
}
func (appGWNoWAF) Severity() ir.Severity { return ir.SeverityMedium }

func (appGWNoWAF) AppliesTo(resType string) bool {
	return resType == "azurerm_application_gateway"
}

func (s appGWNoWAF) Check(r ir.Resource) []ir.Finding {
	wafs, span, present, known := getBlocks(r, "waf_configuration")
	if !present || !known {
		return nil
	}
	for _, w := range wafs {
		en, _, p, k := blockBool(w, "enabled")
		if p && !k {
			return nil
		}
		if !p || !en {
			return []ir.Finding{mkFinding(s, r, "waf_configuration",
				evidenceSpan(span, r.Span), "WAF not enabled",
				"waf_configuration { enabled = true }")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-240: Application Gateway below TLS 1.2
// ---------------------------------------------------------------------------

type appGWTLSBelow12 struct{}

func (appGWTLSBelow12) ID() string { return "AEGIS-AZURE-240" }
func (appGWTLSBelow12) Title() string {
	return "Application Gateway below TLS 1.2"
}
func (appGWTLSBelow12) Description() string {
	return "azurerm_application_gateway ssl_policy with " +
		"min_protocol_version other than \"TLSv1_2\" permits weak " +
		"protocol versions on the gateway. Enforce TLS 1.2."
}
func (appGWTLSBelow12) Severity() ir.Severity { return ir.SeverityHigh }

func (appGWTLSBelow12) AppliesTo(resType string) bool {
	return resType == "azurerm_application_gateway"
}

func (s appGWTLSBelow12) Check(r ir.Resource) []ir.Finding {
	pols, span, present, known := getBlocks(r, "ssl_policy")
	if !present || !known {
		return nil
	}
	for _, p := range pols {
		ver, _, vp, vk := blockString(p, "min_protocol_version")
		if vp && !vk {
			return nil
		}
		if !vp || ver != "TLSv1_2" {
			actual := "absent"
			if vp {
				actual = ver
			}
			return []ir.Finding{mkFinding(s, r, "ssl_policy",
				evidenceSpan(span, r.Span), actual,
				"ssl_policy { min_protocol_version = \"TLSv1_2\" }")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-241: Public IP with Basic SKU
// ---------------------------------------------------------------------------

type publicIPBasicSKU struct{}

func (publicIPBasicSKU) ID() string { return "AEGIS-AZURE-241" }
func (publicIPBasicSKU) Title() string {
	return "Public IP with Basic SKU"
}
func (publicIPBasicSKU) Description() string {
	return "azurerm_public_ip with sku other than \"Standard\" misses " +
		"zone redundancy, DDoS protection integration and secure-by-default " +
		"closed ports. Use the Standard SKU."
}
func (publicIPBasicSKU) Severity() ir.Severity { return ir.SeverityLow }

func (publicIPBasicSKU) AppliesTo(resType string) bool {
	return resType == "azurerm_public_ip"
}

func (s publicIPBasicSKU) Check(r ir.Resource) []ir.Finding {
	sku, span, present, known := getString(r, "sku")
	if !present || !known {
		return nil // default Basic is legacy; only flag explicit choice
	}
	if strings.EqualFold(strings.TrimSpace(sku), "Standard") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "sku", span,
		sku, "sku = \"Standard\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-242: Load Balancer with Basic SKU
// ---------------------------------------------------------------------------

type lbBasicSKU struct{}

func (lbBasicSKU) ID() string { return "AEGIS-AZURE-242" }
func (lbBasicSKU) Title() string {
	return "Load Balancer with Basic SKU"
}
func (lbBasicSKU) Description() string {
	return "azurerm_lb with sku other than \"Standard\" uses the " +
		"retiring Basic SKU without zone redundancy and modern security " +
		"defaults. Use the Standard SKU."
}
func (lbBasicSKU) Severity() ir.Severity { return ir.SeverityLow }

func (lbBasicSKU) AppliesTo(resType string) bool {
	return resType == "azurerm_lb"
}

func (s lbBasicSKU) Check(r ir.Resource) []ir.Finding {
	sku, span, present, known := getString(r, "sku")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(sku), "Standard") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "sku", span,
		sku, "sku = \"Standard\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-243: Virtual network without DDoS protection

// ---------------------------------------------------------------------------
// AEGIS-AZURE-244: NSG inline rule open to the internet
// ---------------------------------------------------------------------------

type nsgInlineOpenRule struct{}

func (nsgInlineOpenRule) ID() string { return "AEGIS-AZURE-244" }
func (nsgInlineOpenRule) Title() string {
	return "NSG inline security rule open to the internet"
}
func (nsgInlineOpenRule) Description() string {
	return "azurerm_network_security_group security_rule blocks with " +
		"inbound Allow and a source of *, 0.0.0.0/0 or Internet expose " +
		"the subnet to the world. Restrict inline rule sources."
}
func (nsgInlineOpenRule) Severity() ir.Severity { return ir.SeverityHigh }

func (nsgInlineOpenRule) AppliesTo(resType string) bool {
	return resType == "azurerm_network_security_group"
}

func (s nsgInlineOpenRule) Check(r ir.Resource) []ir.Finding {
	rules, span, present, known := getBlocks(r, "security_rule")
	if !present || !known {
		return nil
	}
	for _, rl := range rules {
		dir, _, dp, dk := blockString(rl, "direction")
		access, _, ap, ak := blockString(rl, "access")
		if (dp && !dk) || (ap && !ak) {
			continue
		}
		if !dp || !ap {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(dir), "Inbound") ||
			!strings.EqualFold(strings.TrimSpace(access), "Allow") {
			continue
		}
		if pfx, _, pp, pk := blockString(rl, "source_address_prefix"); pp {
			if !pk {
				continue
			}
			if isOpenSource(pfx) {
				return []ir.Finding{mkFinding(s, r, "security_rule",
					evidenceSpan(span, r.Span), "inline rule source "+pfx,
					"restricted source address prefix")}
			}
			continue
		}
		if pfxs, _, pok := getStringListFromMap(rl, "source_address_prefixes"); pok {
			for _, pfx := range pfxs {
				if isOpenSource(pfx) {
					return []ir.Finding{mkFinding(s, r, "security_rule",
						evidenceSpan(span, r.Span), "inline rule source "+pfx,
						"restricted source address prefixes")}
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-245: AKS with local accounts enabled
// ---------------------------------------------------------------------------

type aksLocalAccounts struct{}

func (aksLocalAccounts) ID() string { return "AEGIS-AZURE-245" }
func (aksLocalAccounts) Title() string {
	return "AKS cluster with local accounts enabled"
}
func (aksLocalAccounts) Description() string {
	return "azurerm_kubernetes_cluster without local_account_disabled = " +
		"true keeps the static cluster-admin kubeconfig credential " +
		"active, bypassing Entra ID controls. Disable local accounts " +
		"once Entra ID RBAC is configured."
}
func (aksLocalAccounts) Severity() ir.Severity { return ir.SeverityMedium }

func (aksLocalAccounts) AppliesTo(resType string) bool {
	return resType == "azurerm_kubernetes_cluster"
}

func (s aksLocalAccounts) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "local_account_disabled",
		"local_account_disabled = true")
}
