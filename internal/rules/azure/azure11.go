// Package azure — App Service hardening rules, round 3 (AEGIS-AZURE-137..143).
//
// Gaps not covered by AEGIS-AZURE-011/012, 061..068 or 109..118 (HTTPS-only,
// TLS, auth, managed identity, VNet integration, FTPS, remote debugging,
// health check, slot HTTPS, client certs, detailed errors, failed-request
// tracing, HTTP logging, HTTP/2, storage mounts): access restrictions for
// the site and the SCM endpoint, CORS wildcard origins, missing backups,
// missing application logs, and allow-all IP restriction rules.
//
// Absent-attribute policy for this file: an absent site_config means the
// provider defaults apply (no IP restrictions, FTP/SCM open), so absent
// yields a finding. Present-but-unresolved values yield NO finding.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure11Rules returns App Service hardening rules in ID order.
func Azure11Rules() []ir.Rule {
	return []ir.Rule{
		appSvcNoIPRestrictions{},  // AEGIS-AZURE-137
		appSvcNoSCMRestrictions{}, // AEGIS-AZURE-138
		appSvcCORSWildcard{},      // AEGIS-AZURE-139
		appSvcNoBackup{},          // AEGIS-AZURE-140
		appSvcNoAppLogs{},         // AEGIS-AZURE-141
		appSvcAllowAllIPRule{},    // AEGIS-AZURE-142
		appSvcCORSCredentials{},   // AEGIS-AZURE-143
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-137: App Service without IP access restrictions
// ---------------------------------------------------------------------------

type appSvcNoIPRestrictions struct{}

func (appSvcNoIPRestrictions) ID() string { return "AEGIS-AZURE-137" }
func (appSvcNoIPRestrictions) Title() string {
	return "App Service without IP access restrictions"
}
func (appSvcNoIPRestrictions) Description() string {
	return "Web app site_config without ip_restriction blocks accepts " +
		"traffic from any source address. Add ip_restriction rules to " +
		"allow-list the networks that may reach the app."
}
func (appSvcNoIPRestrictions) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcNoIPRestrictions) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcNoIPRestrictions) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present || !known || len(blks) == 0 {
		// No site_config: provider default is unrestricted access.
		return []ir.Finding{mkFinding(s, r, "site_config.ip_restriction",
			evidenceSpan(ir.Span{}, r.Span), "absent (default allow all)",
			"site_config { ip_restriction { ip_address = \"203.0.113.0/24\" } }")}
	}
	if len(blockList(blks[0], "ip_restriction")) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "site_config.ip_restriction",
		evidenceSpan(ir.Span{}, r.Span), "absent (default allow all)",
		"site_config { ip_restriction { ip_address = \"203.0.113.0/24\" } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-138: App Service SCM endpoint without access restrictions
// ---------------------------------------------------------------------------

type appSvcNoSCMRestrictions struct{}

func (appSvcNoSCMRestrictions) ID() string { return "AEGIS-AZURE-138" }
func (appSvcNoSCMRestrictions) Title() string {
	return "App Service SCM site without access restrictions"
}
func (appSvcNoSCMRestrictions) Description() string {
	return "Web app site_config without scm_ip_restriction blocks (or " +
		"scm_use_main_ip_restriction = true) leaves the Kudu SCM/deployment " +
		"endpoint reachable from any address. Restrict the SCM site to " +
		"trusted networks."
}
func (appSvcNoSCMRestrictions) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcNoSCMRestrictions) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcNoSCMRestrictions) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	mk := func(actual string) []ir.Finding {
		return []ir.Finding{mkFinding(s, r, "site_config.scm_ip_restriction",
			evidenceSpan(ir.Span{}, r.Span), actual,
			"scm_ip_restriction { ip_address = \"203.0.113.0/24\" } or scm_use_main_ip_restriction = true")}
	}
	if !present || !known || len(blks) == 0 {
		return mk("absent (default allow all)")
	}
	sc := blks[0]
	use, _, up, uk := blockBool(sc, "scm_use_main_ip_restriction")
	if up && !uk {
		return nil // unresolved: cannot decide
	}
	if up && use {
		return nil // inherits the main site restrictions
	}
	if len(blockList(sc, "scm_ip_restriction")) > 0 {
		return nil
	}
	return mk("absent (default allow all)")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-139: App Service CORS allows any origin
// ---------------------------------------------------------------------------

type appSvcCORSWildcard struct{}

func (appSvcCORSWildcard) ID() string { return "AEGIS-AZURE-139" }
func (appSvcCORSWildcard) Title() string {
	return "App Service CORS allows any origin"
}
func (appSvcCORSWildcard) Description() string {
	return "Web app site_config.cors with allowed_origins containing \"*\" " +
		"lets any website make cross-origin requests to the app. Restrict " +
		"allowed_origins to the domains that need access."
}
func (appSvcCORSWildcard) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcCORSWildcard) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcCORSWildcard) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present || !known || len(blks) == 0 {
		return nil // no CORS configured: nothing to flag
	}
	for _, cors := range blockList(blks[0], "cors") {
		origins, _, ok := getStringListFromBlock(cors, "allowed_origins")
		if !ok {
			return nil // unresolved: cannot decide
		}
		for _, o := range origins {
			if strings.TrimSpace(o) == "*" {
				return []ir.Finding{mkFinding(s, r, "site_config.cors.allowed_origins",
					evidenceSpan(ir.Span{}, r.Span), "*",
					"allowed_origins = [\"https://example.com\"]")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-140: App Service without backup configuration
// ---------------------------------------------------------------------------

type appSvcNoBackup struct{}

func (appSvcNoBackup) ID() string { return "AEGIS-AZURE-140" }
func (appSvcNoBackup) Title() string {
	return "App Service without backup configuration"
}
func (appSvcNoBackup) Description() string {
	return "Hygiene: web app without a backup block has no scheduled " +
		"backups of app content and configuration, slowing recovery from " +
		"misconfiguration or compromise. Configure automated backups."
}
func (appSvcNoBackup) Severity() ir.Severity { return ir.SeverityLow }

func (appSvcNoBackup) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcNoBackup) Check(r ir.Resource) []ir.Finding {
	if _, _, present, _ := getBlocks(r, "backup"); present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "backup",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"backup { name = \"...\" storage_account_url = \"...\" schedule { frequency_interval = 1 frequency_unit = \"Day\" } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-141: App Service without application logs
// ---------------------------------------------------------------------------

type appSvcNoAppLogs struct{}

func (appSvcNoAppLogs) ID() string { return "AEGIS-AZURE-141" }
func (appSvcNoAppLogs) Title() string {
	return "App Service without application logs"
}
func (appSvcNoAppLogs) Description() string {
	return "Web app logs block without application_logs loses the " +
		"application diagnostic stream needed to detect abuse or " +
		"compromise. Enable application logging to storage or the file " +
		"system. (HTTP request logging: AEGIS-AZURE-114.)"
}
func (appSvcNoAppLogs) Severity() ir.Severity { return ir.SeverityLow }

func (appSvcNoAppLogs) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcNoAppLogs) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "logs")
	if present && known {
		for _, b := range blks {
			if len(blockList(b, "application_logs")) > 0 {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "logs.application_logs",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"logs { application_logs { file_system_level = \"Warning\" } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-142: App Service IP restriction allows all traffic
// ---------------------------------------------------------------------------

type appSvcAllowAllIPRule struct{}

func (appSvcAllowAllIPRule) ID() string { return "AEGIS-AZURE-142" }
func (appSvcAllowAllIPRule) Title() string {
	return "App Service IP restriction allows all traffic"
}
func (appSvcAllowAllIPRule) Description() string {
	return "Web app site_config.ip_restriction with an Allow rule for " +
		"0.0.0.0/0 defeats the access restriction entirely. Remove the " +
		"allow-all rule and allow-list only trusted networks."
}
func (appSvcAllowAllIPRule) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcAllowAllIPRule) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcAllowAllIPRule) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present || !known || len(blks) == 0 {
		return nil // no restrictions at all: AEGIS-AZURE-137's finding
	}
	for _, rule := range blockList(blks[0], "ip_restriction") {
		action, _, aPresent, aKnown := blockString(rule, "action")
		if aPresent && !aKnown {
			return nil
		}
		if aPresent && !strings.EqualFold(strings.TrimSpace(action), "Allow") {
			continue // Deny rules are fine
		}
		ip, span, iPresent, iKnown := blockString(rule, "ip_address")
		if iPresent && !iKnown {
			return nil
		}
		if iPresent && strings.TrimSpace(ip) == "0.0.0.0/0" {
			return []ir.Finding{mkFinding(s, r, "site_config.ip_restriction.ip_address",
				evidenceSpan(span, r.Span), "0.0.0.0/0 (Allow)",
				"remove the allow-all rule; allow-list trusted networks")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-143: App Service CORS allows credentials
// ---------------------------------------------------------------------------

type appSvcCORSCredentials struct{}

func (appSvcCORSCredentials) ID() string { return "AEGIS-AZURE-143" }
func (appSvcCORSCredentials) Title() string {
	return "App Service CORS allows credentials"
}
func (appSvcCORSCredentials) Description() string {
	return "Web app site_config.cors with support_credentials = true lets " +
		"another origin's site send the user's cookies/credentials to the " +
		"app on their behalf. Disable credential support unless " +
		"cross-origin authenticated calls are required."
}
func (appSvcCORSCredentials) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcCORSCredentials) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcCORSCredentials) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present || !known || len(blks) == 0 {
		return nil
	}
	for _, cors := range blockList(blks[0], "cors") {
		creds, span, cPresent, cKnown := blockBool(cors, "support_credentials")
		if cPresent && !cKnown {
			return nil
		}
		if cPresent && creds {
			return []ir.Finding{mkFinding(s, r, "site_config.cors.support_credentials",
				evidenceSpan(span, r.Span), "true",
				"support_credentials = false")}
		}
	}
	return nil
}
