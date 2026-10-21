// Package azure — SQL, NSG and network rules (AEGIS-AZURE-044..060).
package azure

import (
	"sort"
	"strings"

	"aegis/internal/ir"
)

// Azure4Rules returns SQL, NSG and network rules in ID order.
func Azure4Rules() []ir.Rule {
	return []ir.Rule{
		mssqlNoTDE{},              // AEGIS-AZURE-044
		mssqlNoThreatDetect{},     // AEGIS-AZURE-046
		mssqlDBNoTDE{},            // AEGIS-AZURE-049
		mssqlFirewallOpen{},       // AEGIS-AZURE-050
		mssqlNoVulnAssess{},       // AEGIS-AZURE-051
		mssqlShortBackup{},        // AEGIS-AZURE-052
		nsgRDPPublic{},            // AEGIS-AZURE-053
		nsgSSHPublic{},            // AEGIS-AZURE-054
		nsgWildcardPort{},         // AEGIS-AZURE-055
		nsgNoFlowLog{},            // AEGIS-AZURE-056 (absence-based, fires on explicit disable)
		vnetNoDDoS{},              // AEGIS-AZURE-057
		vnetNoFlowTimeout{},       // AEGIS-AZURE-058
		subnetNoNSG{},             // AEGIS-AZURE-059
		subnetNoServiceEndpoint{}, // AEGIS-AZURE-060
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-044: MSSQL server without transparent data encryption
// ---------------------------------------------------------------------------

type mssqlNoTDE struct{}

func (mssqlNoTDE) ID() string { return "AEGIS-AZURE-044" }
func (mssqlNoTDE) Title() string {
	return "MSSQL server without transparent data encryption"
}
func (mssqlNoTDE) Description() string {
	return "azurerm_mssql_server without transparent_data_encryption_enabled " +
		"stores data unencrypted at rest. Enable TDE."
}
func (mssqlNoTDE) Severity() ir.Severity { return ir.SeverityHigh }

func (mssqlNoTDE) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server"
}

func (s mssqlNoTDE) Check(r ir.Resource) []ir.Finding {
	enc, span, present, known := getBool(r, "transparent_data_encryption_enabled")
	if !present || !known {
		return nil
	}
	if enc {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "transparent_data_encryption_enabled", span,
		"false", "transparent_data_encryption_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-046: MSSQL server without threat detection
// ---------------------------------------------------------------------------

type mssqlNoThreatDetect struct{}

func (mssqlNoThreatDetect) ID() string { return "AEGIS-AZURE-046" }
func (mssqlNoThreatDetect) Title() string {
	return "MSSQL server without security alert policy"
}
func (mssqlNoThreatDetect) Description() string {
	return "azurerm_mssql_server without security_alert_policy misses " +
		"advanced threat detection. Enable security alerts."
}
func (mssqlNoThreatDetect) Severity() ir.Severity { return ir.SeverityMedium }

func (mssqlNoThreatDetect) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server"
}

func (s mssqlNoThreatDetect) Check(r ir.Resource) []ir.Finding {
	_, _, present, _ := getBlocks(r, "security_alert_policy")
	if present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "security_alert_policy",
		evidenceSpan(ir.Span{}, r.Span), "absent", "security_alert_policy block with state = \"Enabled\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-049: MSSQL database without transparent data encryption
// ---------------------------------------------------------------------------

type mssqlDBNoTDE struct{}

func (mssqlDBNoTDE) ID() string { return "AEGIS-AZURE-049" }
func (mssqlDBNoTDE) Title() string {
	return "MSSQL database without transparent data encryption"
}
func (mssqlDBNoTDE) Description() string {
	return "azurerm_mssql_database with transparent_data_encryption_enabled = false " +
		"stores data unencrypted. Enable TDE."
}
func (mssqlDBNoTDE) Severity() ir.Severity { return ir.SeverityHigh }

func (mssqlDBNoTDE) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_database"
}

func (s mssqlDBNoTDE) Check(r ir.Resource) []ir.Finding {
	enc, span, present, known := getBool(r, "transparent_data_encryption_enabled")
	if !present || !known {
		return nil
	}
	if enc {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "transparent_data_encryption_enabled", span,
		"false", "transparent_data_encryption_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-050: MSSQL firewall rule open to the world
// ---------------------------------------------------------------------------

type mssqlFirewallOpen struct{}

func (mssqlFirewallOpen) ID() string { return "AEGIS-AZURE-050" }
func (mssqlFirewallOpen) Title() string {
	return "MSSQL firewall rule allows all IPs"
}
func (mssqlFirewallOpen) Description() string {
	return "azurerm_mssql_firewall_rule with 0.0.0.0 start/end IP allows " +
		"connections from anywhere. Restrict to known ranges."
}
func (mssqlFirewallOpen) Severity() ir.Severity { return ir.SeverityHigh }

func (mssqlFirewallOpen) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_firewall_rule"
}

func (s mssqlFirewallOpen) Check(r ir.Resource) []ir.Finding {
	start, sspan, spresent, sknown := getString(r, "start_ip_address")
	end, _, epresent, eknown := getString(r, "end_ip_address")
	if !spresent || !sknown || !epresent || !eknown {
		return nil
	}
	if strings.TrimSpace(start) == "0.0.0.0" && strings.TrimSpace(end) == "0.0.0.0" {
		return []ir.Finding{mkFinding(s, r, "start_ip_address", sspan,
			"0.0.0.0 - 0.0.0.0", "restricted start_ip_address/end_ip_address range")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-051: MSSQL server without vulnerability assessment
// ---------------------------------------------------------------------------

type mssqlNoVulnAssess struct{}

func (mssqlNoVulnAssess) ID() string { return "AEGIS-AZURE-051" }
func (mssqlNoVulnAssess) Title() string {
	return "MSSQL server without vulnerability assessment"
}
func (mssqlNoVulnAssess) Description() string {
	return "azurerm_mssql_server without mssql_server_vulnerability_assessment " +
		"misses recurring vulnerability scans. Enable the assessment."
}
func (mssqlNoVulnAssess) Severity() ir.Severity { return ir.SeverityLow }

func (mssqlNoVulnAssess) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server_vulnerability_assessment"
}

func (s mssqlNoVulnAssess) Check(r ir.Resource) []ir.Finding {
	// This rule flags the assessment resource itself when disabled via
	// recurring_scans; absence of the resource is handled by documentation.
	blks, _, present, known := getBlocks(r, "recurring_scans")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	en, _, ep, ek := blockString(blks[0], "enabled")
	if !ep || !ek {
		return nil
	}
	if strings.EqualFold(en, "true") {
		return nil
	}
	// An empty value is not an explicit enable: keep firing, but report
	// a non-empty Actual so the evidence is meaningful.
	actual := en
	if actual == "" {
		actual = "(empty — not enabled)"
	}
	return []ir.Finding{mkFinding(s, r, "recurring_scans.enabled",
		evidenceSpan(ir.Span{}, r.Span), actual, "recurring_scans { enabled = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-052: MSSQL database with short backup retention
// ---------------------------------------------------------------------------

type mssqlShortBackup struct{}

func (mssqlShortBackup) ID() string { return "AEGIS-AZURE-052" }
func (mssqlShortBackup) Title() string {
	return "MSSQL database with short backup retention"
}
func (mssqlShortBackup) Description() string {
	return "azurerm_mssql_database with short_term_retention_policy " +
		"retention_days < 7 risks data loss. Retain backups at least 7 days."
}
func (mssqlShortBackup) Severity() ir.Severity { return ir.SeverityLow }

func (mssqlShortBackup) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_database"
}

func (s mssqlShortBackup) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "short_term_retention_policy")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	dv, ok := blks[0]["retention_days"]
	if !ok || !dv.Known {
		return nil
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
	if days >= 7 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "short_term_retention_policy.retention_days",
		dv.Span, "less than 7", "retention_days >= 7")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-053: NSG rule allows RDP from the internet
// ---------------------------------------------------------------------------

type nsgRDPPublic struct{}

func (nsgRDPPublic) ID() string { return "AEGIS-AZURE-053" }
func (nsgRDPPublic) Title() string {
	return "NSG rule allows RDP from the internet"
}
func (nsgRDPPublic) Description() string {
	return "azurerm_network_security_rule allowing TCP 3389 from * or " +
		"0.0.0.0/0 exposes RDP. Restrict source addresses."
}
func (nsgRDPPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (nsgRDPPublic) AppliesTo(resType string) bool {
	return resType == "azurerm_network_security_rule" ||
		resType == "azurerm_network_security_group"
}

func (s nsgRDPPublic) Check(r ir.Resource) []ir.Finding {
	return checkNSGPortOpen(s, r, "3389", "RDP")
}

// checkNSGPortOpen is shared by port-specific NSG rules.
func checkNSGPortOpen(rule ir.Rule, r ir.Resource, port, name string) []ir.Finding {
	// Direct rule resource
	if r.Type == "azurerm_network_security_rule" {
		if nsgRuleOpenToWorld(r, port) {
			return []ir.Finding{mkFinding(rule, r, "destination_port_range",
				evidenceSpan(ir.Span{}, r.Span), port+" from *",
				"destination_port_range restricted, source limited")}
		}
		return nil
	}
	// Inline rules inside NSG
	blks, _, present, known := getBlocks(r, "security_rule")
	if !present || !known {
		return nil
	}
	for _, blk := range blks {
		if nsgBlockOpenToWorld(blk, port) {
			return []ir.Finding{mkFinding(rule, r, "security_rule",
				evidenceSpan(ir.Span{}, r.Span), name+" open to *",
				"restrict source_address_prefix")}
		}
	}
	return nil
}

// nsgRuleOpenToWorld checks a standalone rule resource.
func nsgRuleOpenToWorld(r ir.Resource, port string) bool {
	dir, _, dp, dk := getString(r, "direction")
	if !dp || !dk || !strings.EqualFold(dir, "Inbound") {
		return false
	}
	acc, _, ap, ak := getString(r, "access")
	if !ap || !ak || !strings.EqualFold(acc, "Allow") {
		return false
	}
	proto, _, pp, pk := getString(r, "protocol")
	if !pp || !pk || !strings.EqualFold(proto, "Tcp") && proto != "*" {
		return false
	}
	dpr, _, drp, drk := getString(r, "destination_port_range")
	if !drp || !drk {
		// check ranges list
		if lst, _, ok := getStringList(r, "destination_port_ranges"); ok {
			for _, p := range lst {
				if strings.TrimSpace(p) == port || p == "*" {
					return nsgSourceOpen(r)
				}
			}
		}
		return false
	}
	if strings.TrimSpace(dpr) != port && dpr != "*" {
		return false
	}
	return nsgSourceOpen(r)
}

// nsgSourceOpen checks whether the source is the world.
func nsgSourceOpen(r ir.Resource) bool {
	if sp, _, pp, pk := getString(r, "source_address_prefix"); pp && pk {
		if sp == "*" || sp == "0.0.0.0/0" || strings.EqualFold(sp, "Internet") {
			return true
		}
	}
	if lst, _, ok := getStringList(r, "source_address_prefixes"); ok {
		for _, p := range lst {
			if p == "*" || p == "0.0.0.0/0" || strings.EqualFold(p, "Internet") {
				return true
			}
		}
	}
	return false
}

// nsgBlockOpenToWorld checks an inline security_rule block.
func nsgBlockOpenToWorld(blk map[string]ir.Value, port string) bool {
	dir, _, dp, dk := blockString(blk, "direction")
	if !dp || !dk || !strings.EqualFold(dir, "Inbound") {
		return false
	}
	acc, _, ap, ak := blockString(blk, "access")
	if !ap || !ak || !strings.EqualFold(acc, "Allow") {
		return false
	}
	proto, _, pp, pk := blockString(blk, "protocol")
	if !pp || !pk || !strings.EqualFold(proto, "Tcp") && proto != "*" {
		return false
	}
	matched := false
	if dpr, _, drp, drk := blockString(blk, "destination_port_range"); drp && drk {
		if strings.TrimSpace(dpr) == port || dpr == "*" {
			matched = true
		}
	}
	if !matched {
		if v, ok := blk["destination_port_ranges"]; ok && v.Known {
			if l, lok := v.AsList(); lok {
				for _, item := range l {
					if ps, sok := item.AsString(); sok &&
						(strings.TrimSpace(ps) == port || ps == "*") {
						matched = true
					}
				}
			}
		}
	}
	if !matched {
		return false
	}
	if sp, _, spp, spk := blockString(blk, "source_address_prefix"); spp && spk {
		if sp == "*" || sp == "0.0.0.0/0" || strings.EqualFold(sp, "Internet") {
			return true
		}
	}
	if v, ok := blk["source_address_prefixes"]; ok && v.Known {
		if l, lok := v.AsList(); lok {
			for _, item := range l {
				if ps, sok := item.AsString(); sok &&
					(ps == "*" || ps == "0.0.0.0/0" || strings.EqualFold(ps, "Internet")) {
					return true
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-054: NSG rule allows SSH from the internet
// ---------------------------------------------------------------------------

type nsgSSHPublic struct{}

func (nsgSSHPublic) ID() string { return "AEGIS-AZURE-054" }
func (nsgSSHPublic) Title() string {
	return "NSG rule allows SSH from the internet"
}
func (nsgSSHPublic) Description() string {
	return "azurerm_network_security_rule allowing TCP 22 from * or " +
		"0.0.0.0/0 exposes SSH. Restrict source addresses or use Azure Bastion."
}
func (nsgSSHPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (nsgSSHPublic) AppliesTo(resType string) bool {
	return resType == "azurerm_network_security_rule" ||
		resType == "azurerm_network_security_group"
}

func (s nsgSSHPublic) Check(r ir.Resource) []ir.Finding {
	return checkNSGPortOpen(s, r, "22", "SSH")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-055: NSG rule with wildcard destination port
// ---------------------------------------------------------------------------

type nsgWildcardPort struct{}

func (nsgWildcardPort) ID() string { return "AEGIS-AZURE-055" }
func (nsgWildcardPort) Title() string {
	return "NSG rule allows all destination ports from the internet"
}
func (nsgWildcardPort) Description() string {
	return "azurerm_network_security_rule with destination_port_range = \"*\" " +
		"and a public source exposes every port. Scope destination ports."
}
func (nsgWildcardPort) Severity() ir.Severity { return ir.SeverityHigh }

func (nsgWildcardPort) AppliesTo(resType string) bool {
	return resType == "azurerm_network_security_rule" ||
		resType == "azurerm_network_security_group"
}

func (s nsgWildcardPort) Check(r ir.Resource) []ir.Finding {
	return checkNSGPortOpen(s, r, "*", "all ports")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-056: NSG with explicitly disabled flow logs (via diagnostic note)
// ---------------------------------------------------------------------------

type nsgNoFlowLog struct{}

func (nsgNoFlowLog) ID() string { return "AEGIS-AZURE-056" }
func (nsgNoFlowLog) Title() string {
	return "NSG without flow log retention configured"
}
func (nsgNoFlowLog) Description() string {
	return "azurerm_network_watcher_flow_log with retention_policy disabled " +
		"loses network telemetry. Enable flow logs with retention."
}
func (nsgNoFlowLog) Severity() ir.Severity { return ir.SeverityLow }

func (nsgNoFlowLog) AppliesTo(resType string) bool {
	return resType == "azurerm_network_watcher_flow_log"
}

func (s nsgNoFlowLog) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "enabled")
	if !present || !known {
		return nil
	}
	if en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "enabled", span,
		"false", "enabled = true with retention_policy")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-057: Virtual network without DDoS protection
// ---------------------------------------------------------------------------

type vnetNoDDoS struct{}

func (vnetNoDDoS) ID() string { return "AEGIS-AZURE-057" }
func (vnetNoDDoS) Title() string {
	return "Virtual network without DDoS protection plan"
}
func (vnetNoDDoS) Description() string {
	return "azurerm_virtual_network without ddos_protection_plan lacks " +
		"network-layer DDoS mitigation. Associate a DDoS protection plan for " +
		"internet-facing VNets."
}
func (vnetNoDDoS) Severity() ir.Severity { return ir.SeverityLow }

func (vnetNoDDoS) AppliesTo(resType string) bool {
	return resType == "azurerm_virtual_network"
}

func (s vnetNoDDoS) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "ddos_protection_plan")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		for _, b := range blks {
			en, _, p, k := blockBool(b, "enable")
			if p && !k {
				return nil // unresolved: cannot decide
			}
			if p && en {
				return nil // enabled
			}
		}
	}
	actual := "absent"
	if present {
		actual = "not enabled"
	}
	return []ir.Finding{mkFinding(s, r, "ddos_protection_plan",
		evidenceSpan(span, r.Span), actual, "ddos_protection_plan { id = \"...\", enable = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-058: Virtual network without DNS servers
// ---------------------------------------------------------------------------

type vnetNoFlowTimeout struct{}

func (vnetNoFlowTimeout) ID() string { return "AEGIS-AZURE-058" }
func (vnetNoFlowTimeout) Title() string {
	return "Virtual network without custom DNS servers"
}
func (vnetNoFlowTimeout) Description() string {
	return "azurerm_virtual_network without dns_servers relies on Azure " +
		"default DNS. Configure custom DNS for private zone resolution in " +
		"hub-spoke topologies."
}
func (vnetNoFlowTimeout) Severity() ir.Severity { return ir.SeverityLow }

func (vnetNoFlowTimeout) AppliesTo(resType string) bool {
	return resType == "azurerm_virtual_network"
}

func (s vnetNoFlowTimeout) Check(r ir.Resource) []ir.Finding {
	if v, ok := r.Attributes["dns_servers"]; ok && !v.Known {
		return nil // unresolved: cannot decide
	}
	if _, _, ok := getStringList(r, "dns_servers"); ok {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "dns_servers",
		evidenceSpan(ir.Span{}, r.Span), "absent", "dns_servers = [\"10.0.0.4\"]")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-059: Subnet without NSG association
// ---------------------------------------------------------------------------

type subnetNoNSG struct{}

func (subnetNoNSG) ID() string { return "AEGIS-AZURE-059" }
func (subnetNoNSG) Title() string {
	return "Subnet without network security group"
}
func (subnetNoNSG) Description() string {
	return "azurerm_subnet without an associated network security group " +
		"lacks subnet-level filtering. Associate an NSG via " +
		"azurerm_subnet_network_security_group_association."
}
func (subnetNoNSG) Severity() ir.Severity { return ir.SeverityLow }

func (subnetNoNSG) AppliesTo(resType string) bool {
	return resType == "azurerm_subnet"
}

func (s subnetNoNSG) Check(ir.Resource) []ir.Finding { return nil }

var _ ir.CrossResourceRule = subnetNoNSG{}

// CheckAll fires for each subnet with no azurerm_subnet_network_security_group_association
// referencing it. NSG association is a separate resource, so a per-resource Check cannot
// decide this (the subnet itself carries no NSG reference).
func (s subnetNoNSG) CheckAll(resources []ir.Resource) []ir.Finding {
	protected := map[string]bool{}
	for _, r := range resources {
		if r.Type != "azurerm_subnet_network_security_group_association" {
			continue
		}
		v, ok := r.Attributes["subnet_id"]
		if !ok || !v.IsRef() {
			continue // unresolvable link: cannot prove protection
		}
		if addr, ok := refAddrOf(v.Ref); ok {
			protected[addr] = true
		}
	}
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Address() < sorted[j].Address() })
	var out []ir.Finding
	for _, r := range sorted {
		if r.Type != "azurerm_subnet" {
			continue
		}
		if protected[r.Address()] {
			continue
		}
		out = append(out, mkFinding(s, r, "network_security_group",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"azurerm_subnet_network_security_group_association targeting "+r.Address()))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-060: Subnet without service endpoints
// ---------------------------------------------------------------------------

type subnetNoServiceEndpoint struct{}

func (subnetNoServiceEndpoint) ID() string { return "AEGIS-AZURE-060" }
func (subnetNoServiceEndpoint) Title() string {
	return "Subnet without service endpoints for PaaS"
}
func (subnetNoServiceEndpoint) Description() string {
	return "azurerm_subnet without service_endpoints reaches PaaS services " +
		"over the public internet. Add service endpoints for " +
		"Microsoft.Storage, Microsoft.Sql, Microsoft.KeyVault."
}
func (subnetNoServiceEndpoint) Severity() ir.Severity { return ir.SeverityLow }

func (subnetNoServiceEndpoint) AppliesTo(resType string) bool {
	return resType == "azurerm_subnet"
}

func (s subnetNoServiceEndpoint) Check(r ir.Resource) []ir.Finding {
	if v, ok := r.Attributes["service_endpoints"]; ok && !v.Known {
		return nil // unresolved: cannot decide
	}
	if _, _, ok := getStringList(r, "service_endpoints"); ok {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "service_endpoints",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"service_endpoints = [\"Microsoft.Storage\", \"Microsoft.Sql\"]")}
}
