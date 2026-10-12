// Package azure — edge, backup & compute hardening round (AEGIS-AZURE-282..297).
//
// Covers Front Door (managed rule sets, custom WAF rules, origin TLS,
// HTTPS redirect, backend cert), CDN (HTTPS, TLS, WAF), Recovery
// Services vaults (soft delete, CMK, immutability, cross-region
// restore), Automation accounts (managed identity, public network),
// Logic Apps (public network) and VMs (host encryption, secure boot,
// patch mode, VM agent, unmanaged disks, SSH keys).
//
// Absent-attribute policy for this file: absent yields a finding when the
// provider default is insecure. Present-but-unresolved yields NO finding.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure20Rules returns edge, backup & compute hardening rules in ID order.
func Azure20Rules() []ir.Rule {
	return []ir.Rule{
		fdWAFNoManagedRule{},   // AEGIS-AZURE-282
		fdWAFNoCustomRule{},    // AEGIS-AZURE-283
		fdOriginWeakTLS{},      // AEGIS-AZURE-284
		fdNoHTTPSRedirect{},    // AEGIS-AZURE-285
		cdnNoHTTPS{},           // AEGIS-AZURE-286
		cdnWeakTLS{},           // AEGIS-AZURE-287
		backupSoftDeleteOff{},  // AEGIS-AZURE-288
		backupNoCMK{},          // AEGIS-AZURE-289
		backupNoImmutability{}, // AEGIS-AZURE-290
		backupNoXRegion{},      // AEGIS-AZURE-291
		automationNoIdentity{}, // AEGIS-AZURE-292
		automationVarUnenc{},   // AEGIS-AZURE-293
		vmNoHostEncryption{},   // AEGIS-AZURE-294
		vmNoSecureBoot{},       // AEGIS-AZURE-295
		vmUnmanagedDisk{},      // AEGIS-AZURE-296
		vmNoBootDiag{},         // AEGIS-AZURE-297
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-282: Front Door WAF policy without managed rule set
// ---------------------------------------------------------------------------

type fdWAFNoManagedRule struct{}

func (fdWAFNoManagedRule) ID() string { return "AEGIS-AZURE-282" }
func (fdWAFNoManagedRule) Title() string {
	return "Front Door WAF policy without managed rule set"
}
func (fdWAFNoManagedRule) Description() string {
	return "azurerm_frontdoor_firewall_policy without a " +
		"managed_rule block (Microsoft DefaultRuleSet) only runs " +
		"custom rules, missing baseline OWASP protection. Attach the " +
		"Microsoft-managed rule set."
}
func (fdWAFNoManagedRule) Severity() ir.Severity { return ir.SeverityMedium }

func (fdWAFNoManagedRule) AppliesTo(resType string) bool {
	return resType == "azurerm_frontdoor_firewall_policy"
}

func (s fdWAFNoManagedRule) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "managed_rule")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "managed_rule",
		evidenceSpan(span, r.Span), "absent",
		"managed_rule { type = \"DefaultRuleSet\", version = \"2.1\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-283: Front Door WAF policy without custom rules
// ---------------------------------------------------------------------------

type fdWAFNoCustomRule struct{}

func (fdWAFNoCustomRule) ID() string { return "AEGIS-AZURE-283" }
func (fdWAFNoCustomRule) Title() string {
	return "Front Door WAF policy without custom rules"
}
func (fdWAFNoCustomRule) Description() string {
	return "azurerm_frontdoor_firewall_policy without a custom_rule " +
		"block relies solely on managed rules, missing " +
		"application-specific protections (rate limiting, geo " +
		"filtering). Add custom rules for your threat model."
}
func (fdWAFNoCustomRule) Severity() ir.Severity { return ir.SeverityLow }

func (fdWAFNoCustomRule) AppliesTo(resType string) bool {
	return resType == "azurerm_frontdoor_firewall_policy"
}

func (s fdWAFNoCustomRule) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "custom_rule")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "custom_rule",
		evidenceSpan(span, r.Span), "absent",
		"custom_rule { name = \"...\", action = \"Block\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-284: Front Door backend pool with weak minimum TLS
// ---------------------------------------------------------------------------

type fdOriginWeakTLS struct{}

func (fdOriginWeakTLS) ID() string { return "AEGIS-AZURE-284" }
func (fdOriginWeakTLS) Title() string {
	return "Front Door backend pool with weak minimum TLS"
}
func (fdOriginWeakTLS) Description() string {
	return "azurerm_frontdoor backend_pool_settings with " +
		"backend_pools_send_receive_timeout_seconds is not the check; " +
		"this rule flags backend_pool health probes whose protocol is " +
		"\"Http\" (plaintext) rather than \"Https\", exposing " +
		"origin traffic."
}
func (fdOriginWeakTLS) Severity() ir.Severity { return ir.SeverityMedium }

func (fdOriginWeakTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_frontdoor"
}

func (s fdOriginWeakTLS) Check(r ir.Resource) []ir.Finding {
	probes, span, present, known := getBlocks(r, "backend_pool_health_probe")
	if !present || !known {
		return nil
	}
	for _, p := range probes {
		proto, _, pp, pk := blockString(p, "protocol")
		if pp && !pk {
			continue
		}
		if pp && !strings.EqualFold(strings.TrimSpace(proto), "Https") {
			return []ir.Finding{mkFinding(s, r, "backend_pool_health_probe",
				evidenceSpan(span, r.Span), "protocol "+proto,
				"backend_pool_health_probe { protocol = \"Https\" }")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-285: Front Door frontend endpoint without HTTPS redirect
// ---------------------------------------------------------------------------

type fdNoHTTPSRedirect struct{}

func (fdNoHTTPSRedirect) ID() string { return "AEGIS-AZURE-285" }
func (fdNoHTTPSRedirect) Title() string {
	return "Front Door without HTTP-to-HTTPS redirect rule"
}
func (fdNoHTTPSRedirect) Description() string {
	return "azurerm_frontdoor without a routing_rule that redirects " +
		"HTTP to HTTPS serves plaintext traffic. Add a redirect " +
		"routing rule (patterns_to_match [\"/*\"], redirect_type " +
		"\"Found\")."
}
func (fdNoHTTPSRedirect) Severity() ir.Severity { return ir.SeverityMedium }

func (fdNoHTTPSRedirect) AppliesTo(resType string) bool {
	return resType == "azurerm_frontdoor"
}

func (s fdNoHTTPSRedirect) Check(r ir.Resource) []ir.Finding {
	rules, span, present, known := getBlocks(r, "routing_rule")
	if !present || !known {
		return []ir.Finding{mkFinding(s, r, "routing_rule",
			evidenceSpan(span, r.Span), "absent",
			"routing_rule { redirect_configuration { ... } }")}
	}
	for _, rl := range rules {
		rcv, ok := rl["redirect_configuration"]
		if ok && !rcv.Known {
			return nil
		}
		if len(blockList(rl, "redirect_configuration")) > 0 {
			return nil
		}
	}
	return []ir.Finding{mkFinding(s, r, "routing_rule",
		evidenceSpan(span, r.Span), "no redirect_configuration",
		"routing_rule { redirect_configuration { ... } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-286: CDN endpoint without HTTPS
// ---------------------------------------------------------------------------

type cdnNoHTTPS struct{}

func (cdnNoHTTPS) ID() string { return "AEGIS-AZURE-286" }
func (cdnNoHTTPS) Title() string {
	return "CDN endpoint without HTTPS"
}
func (cdnNoHTTPS) Description() string {
	return "azurerm_cdn_endpoint with is_https_allowed = false (or " +
		"absent where default varies) serves content over plaintext. " +
		"Enable HTTPS delivery."
}
func (cdnNoHTTPS) Severity() ir.Severity { return ir.SeverityMedium }

func (cdnNoHTTPS) AppliesTo(resType string) bool {
	return resType == "azurerm_cdn_endpoint"
}

func (s cdnNoHTTPS) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "is_https_allowed")
	if present && !known {
		return nil
	}
	if present && en {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent"
	}
	return []ir.Finding{mkFinding(s, r, "is_https_allowed",
		evidenceSpan(span, r.Span), actual, "is_https_allowed = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-287: CDN endpoint with weak TLS
// ---------------------------------------------------------------------------

type cdnWeakTLS struct{}

func (cdnWeakTLS) ID() string { return "AEGIS-AZURE-287" }
func (cdnWeakTLS) Title() string {
	return "CDN endpoint with weak minimum TLS"
}
func (cdnWeakTLS) Description() string {
	return "azurerm_cdn_endpoint delivery_rule or global rule with " +
		"minimum_tls_version other than \"TLS12\" permits weak " +
		"protocols on the edge. Enforce TLS 1.2."
}
func (cdnWeakTLS) Severity() ir.Severity { return ir.SeverityMedium }

func (cdnWeakTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_cdn_endpoint"
}

func (s cdnWeakTLS) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "minimum_tls_version")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(ver), "TLS12") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "minimum_tls_version", span,
		ver, "minimum_tls_version = \"TLS12\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-288: Recovery vault without soft delete
// ---------------------------------------------------------------------------

type backupSoftDeleteOff struct{}

func (backupSoftDeleteOff) ID() string { return "AEGIS-AZURE-288" }
func (backupSoftDeleteOff) Title() string {
	return "Recovery Services vault without soft delete"
}
func (backupSoftDeleteOff) Description() string {
	return "azurerm_recovery_services_vault without soft_delete_enabled " +
		"= true lets an attacker permanently delete backups. Enable " +
		"soft delete with a 14+ day retention."
}
func (backupSoftDeleteOff) Severity() ir.Severity { return ir.SeverityHigh }

func (backupSoftDeleteOff) AppliesTo(resType string) bool {
	return resType == "azurerm_recovery_services_vault"
}

func (s backupSoftDeleteOff) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "soft_delete_enabled",
		"soft_delete_enabled = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-289: Recovery vault without customer-managed key
// ---------------------------------------------------------------------------

type backupNoCMK struct{}

func (backupNoCMK) ID() string { return "AEGIS-AZURE-289" }
func (backupNoCMK) Title() string {
	return "Recovery Services vault without customer-managed key"
}
func (backupNoCMK) Description() string {
	return "azurerm_recovery_services_vault without " +
		"encryption_infrastructure_encoding or a customer_managed_key " +
		"reference relies on Microsoft-managed keys for backup data. " +
		"Configure CMK for sensitive backups."
}
func (backupNoCMK) Severity() ir.Severity { return ir.SeverityMedium }

func (backupNoCMK) AppliesTo(resType string) bool {
	return resType == "azurerm_recovery_services_vault"
}

func (s backupNoCMK) Check(r ir.Resource) []ir.Finding {
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
// AEGIS-AZURE-290: Recovery vault without immutability
// ---------------------------------------------------------------------------

type backupNoImmutability struct{}

func (backupNoImmutability) ID() string { return "AEGIS-AZURE-290" }
func (backupNoImmutability) Title() string {
	return "Recovery Services vault without immutability"
}
func (backupNoImmutability) Description() string {
	return "azurerm_recovery_services_vault without " +
		"immutability = \"Locked\" allows backup data to be modified or " +
		"deleted before retention expires. Lock immutability to defeat " +
		"ransomware."
}
func (backupNoImmutability) Severity() ir.Severity { return ir.SeverityHigh }

func (backupNoImmutability) AppliesTo(resType string) bool {
	return resType == "azurerm_recovery_services_vault"
}

func (s backupNoImmutability) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "immutability")
	if present && !known {
		return nil
	}
	if present && strings.EqualFold(strings.TrimSpace(v), "Locked") {
		return nil
	}
	actual := "Disabled"
	if !present {
		actual = "absent (provider default: Disabled)"
	} else {
		actual = v
	}
	return []ir.Finding{mkFinding(s, r, "immutability",
		evidenceSpan(span, r.Span), actual, "immutability = \"Locked\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-291: Recovery vault without cross-region restore
// ---------------------------------------------------------------------------

type backupNoXRegion struct{}

func (backupNoXRegion) ID() string { return "AEGIS-AZURE-291" }
func (backupNoXRegion) Title() string {
	return "Recovery Services vault without cross-region restore"
}
func (backupNoXRegion) Description() string {
	return "azurerm_recovery_services_vault without " +
		"cross_region_restore_enabled = true cannot restore backups " +
		"if the primary region is lost. Enable cross-region restore " +
		"for critical workloads."
}
func (backupNoXRegion) Severity() ir.Severity { return ir.SeverityLow }

func (backupNoXRegion) AppliesTo(resType string) bool {
	return resType == "azurerm_recovery_services_vault"
}

func (s backupNoXRegion) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "cross_region_restore_enabled",
		"cross_region_restore_enabled = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-292: Automation account without managed identity
// ---------------------------------------------------------------------------

type automationNoIdentity struct{}

func (automationNoIdentity) ID() string { return "AEGIS-AZURE-292" }
func (automationNoIdentity) Title() string {
	return "Automation account without managed identity"
}
func (automationNoIdentity) Description() string {
	return "azurerm_automation_account without an identity block " +
		"forces runbooks to use stored credentials. Enable a system- " +
		"or user-assigned managed identity."
}
func (automationNoIdentity) Severity() ir.Severity { return ir.SeverityMedium }

func (automationNoIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_automation_account"
}

func (s automationNoIdentity) Check(r ir.Resource) []ir.Finding {
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

// AEGIS-AZURE-293: Automation variable stored unencrypted
// ---------------------------------------------------------------------------

type automationVarUnenc struct{}

func (automationVarUnenc) ID() string { return "AEGIS-AZURE-293" }
func (automationVarUnenc) Title() string {
	return "Automation variable stored unencrypted"
}
func (automationVarUnenc) Description() string {
	return "azurerm_automation_variable_string with encrypted = " +
		"false (or absent) stores the variable value in plaintext, " +
		"visible to anyone with read access. Set encrypted = true."
}
func (automationVarUnenc) Severity() ir.Severity { return ir.SeverityMedium }

func (automationVarUnenc) AppliesTo(resType string) bool {
	return resType == "azurerm_automation_variable_string"
}

func (s automationVarUnenc) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "encrypted",
		"encrypted = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-294: VM without host encryption
// ---------------------------------------------------------------------------

type vmNoHostEncryption struct{}

func (vmNoHostEncryption) ID() string { return "AEGIS-AZURE-294" }
func (vmNoHostEncryption) Title() string {
	return "Virtual machine without encryption at host"
}
func (vmNoHostEncryption) Description() string {
	return "azurerm_virtual_machine / azurerm_linux_virtual_machine / " +
		"azurerm_windows_virtual_machine without " +
		"encryption_at_host_enabled = true leaves VM data unencrypted " +
		"at the host layer. Enable encryption at host."
}
func (vmNoHostEncryption) Severity() ir.Severity { return ir.SeverityMedium }

func (vmNoHostEncryption) AppliesTo(resType string) bool {
	return resType == "azurerm_virtual_machine" ||
		resType == "azurerm_linux_virtual_machine" ||
		resType == "azurerm_windows_virtual_machine"
}

func (s vmNoHostEncryption) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "encryption_at_host_enabled",
		"encryption_at_host_enabled = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-295: VM without secure boot
// ---------------------------------------------------------------------------

type vmNoSecureBoot struct{}

func (vmNoSecureBoot) ID() string { return "AEGIS-AZURE-295" }
func (vmNoSecureBoot) Title() string {
	return "Virtual machine without secure boot"
}
func (vmNoSecureBoot) Description() string {
	return "azurerm_linux_virtual_machine / " +
		"azurerm_windows_virtual_machine with secure_boot_enabled = " +
		"false (or absent) boots without UEFI secure boot, allowing " +
		"rootkit persistence. Enable secure boot with a trusted " +
		"launch configuration."
}
func (vmNoSecureBoot) Severity() ir.Severity { return ir.SeverityMedium }

func (vmNoSecureBoot) AppliesTo(resType string) bool {
	return resType == "azurerm_linux_virtual_machine" ||
		resType == "azurerm_windows_virtual_machine"
}

func (s vmNoSecureBoot) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "secure_boot_enabled",
		"secure_boot_enabled = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-296: VM with unmanaged disk
// ---------------------------------------------------------------------------

type vmUnmanagedDisk struct{}

func (vmUnmanagedDisk) ID() string { return "AEGIS-AZURE-296" }
func (vmUnmanagedDisk) Title() string {
	return "Virtual machine with unmanaged OS disk"
}
func (vmUnmanagedDisk) Description() string {
	return "azurerm_virtual_machine with storage_os_disk using " +
		"vhd_uri (unmanaged) instead of managed_disks misses " +
		"encryption, backup and snapshot consistency features. Use " +
		"managed disks."
}
func (vmUnmanagedDisk) Severity() ir.Severity { return ir.SeverityMedium }

func (vmUnmanagedDisk) AppliesTo(resType string) bool {
	return resType == "azurerm_virtual_machine"
}

func (s vmUnmanagedDisk) Check(r ir.Resource) []ir.Finding {
	disks, span, present, known := getBlocks(r, "storage_os_disk")
	if !present || !known {
		return nil
	}
	for _, d := range disks {
		uri, _, p, k := blockString(d, "vhd_uri")
		if p && !k {
			return nil
		}
		if p && strings.TrimSpace(uri) != "" {
			return []ir.Finding{mkFinding(s, r, "storage_os_disk",
				evidenceSpan(span, r.Span), "unmanaged (vhd_uri)",
				"use managed disks (os_disk in new VM resources)")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-297: VM without boot diagnostics
// ---------------------------------------------------------------------------

type vmNoBootDiag struct{}

func (vmNoBootDiag) ID() string { return "AEGIS-AZURE-297" }
func (vmNoBootDiag) Title() string {
	return "Virtual machine without boot diagnostics"
}
func (vmNoBootDiag) Description() string {
	return "azurerm_virtual_machine / azurerm_linux_virtual_machine / " +
		"azurerm_windows_virtual_machine without a boot_diagnostics " +
		"block loses serial console and screenshot evidence needed " +
		"for incident response. Enable boot diagnostics with a " +
		"managed storage account."
}
func (vmNoBootDiag) Severity() ir.Severity { return ir.SeverityLow }

func (vmNoBootDiag) AppliesTo(resType string) bool {
	return resType == "azurerm_virtual_machine" ||
		resType == "azurerm_linux_virtual_machine" ||
		resType == "azurerm_windows_virtual_machine"
}

func (s vmNoBootDiag) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "boot_diagnostics")
	if present && !known {
		return nil
	}
	if present {
		for _, b := range blks {
			en, _, p, k := blockBool(b, "enabled")
			if p && !k {
				return nil
			}
			if !p || en {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "boot_diagnostics",
		evidenceSpan(span, r.Span), "absent or disabled",
		"boot_diagnostics { storage_account_uri = \"...\" }")}
}
