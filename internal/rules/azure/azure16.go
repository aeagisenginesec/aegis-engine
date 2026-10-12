// Package azure — SQL & App Service hardening round (AEGIS-AZURE-206..225).
//
// Deepens SQL (TLS, firewall rules, managed instance) and App Service
// (FTPS, HTTP/2, TLS, IP restrictions, client certs, deployment slots).
//
// Absent-attribute policy for this file: absent yields a finding when the
// provider default is insecure. Present-but-unresolved yields NO finding.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure16Rules returns SQL & App Service hardening rules in ID order.
func Azure16Rules() []ir.Rule {
	return []ir.Rule{
		mssqlFirewallWorldOpen{},     // AEGIS-AZURE-207
		sqlFirewallOpenLegacy{},      // AEGIS-AZURE-208
		mssqlMIPublicEndpoint{},      // AEGIS-AZURE-209
		mssqlMIMinTLS{},              // AEGIS-AZURE-210
		appServiceFTPS{},             // AEGIS-AZURE-211
		appServiceNoHTTP2{},          // AEGIS-AZURE-212
		appServiceNoIPRestrict{},     // AEGIS-AZURE-214
		appServiceNoClientCert{},     // AEGIS-AZURE-215
		appServiceSlotNoHTTPS{},      // AEGIS-AZURE-216
		windowsWebAppFTPS{},          // AEGIS-AZURE-217
		windowsWebAppMinTLS{},        // AEGIS-AZURE-218
		windowsWebAppNoIPRestrict{},  // AEGIS-AZURE-219
		linuxWebAppFTPS{},            // AEGIS-AZURE-220
		linuxWebAppMinTLS{},          // AEGIS-AZURE-221
		linuxWebAppNoIPRestrict{},    // AEGIS-AZURE-222
		appServiceNoVNet{},           // AEGIS-AZURE-223
		appServiceSlotNoIPRestrict{}, // AEGIS-AZURE-224
		mssqlNoAADAdmin{},            // AEGIS-AZURE-225
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-206: SQL server below TLS 1.2

// ---------------------------------------------------------------------------
// AEGIS-AZURE-207/208: SQL firewall rule open to the world
// ---------------------------------------------------------------------------

type mssqlFirewallWorldOpen struct{}

func (mssqlFirewallWorldOpen) ID() string { return "AEGIS-AZURE-207" }
func (mssqlFirewallWorldOpen) Title() string {
	return "SQL firewall rule open to the internet"
}
func (mssqlFirewallWorldOpen) Description() string {
	return "azurerm_mssql_firewall_rule with start_ip_address 0.0.0.0 " +
		"and end_ip_address 255.255.255.255 exposes the database to the " +
		"entire internet. Restrict firewall rules to known client ranges " +
		"(0.0.0.0-0.0.0.0 alone means \"allow Azure services\" and is " +
		"not flagged)."
}
func (mssqlFirewallWorldOpen) Severity() ir.Severity { return ir.SeverityHigh }

func (mssqlFirewallWorldOpen) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_firewall_rule"
}

func (s mssqlFirewallWorldOpen) Check(r ir.Resource) []ir.Finding {
	return sqlFirewallOpen(s, r)
}

type sqlFirewallOpenLegacy struct{}

func (sqlFirewallOpenLegacy) ID() string { return "AEGIS-AZURE-208" }
func (sqlFirewallOpenLegacy) Title() string {
	return "Legacy SQL firewall rule open to the internet"
}
func (sqlFirewallOpenLegacy) Description() string {
	return "azurerm_sql_firewall_rule with start_ip_address 0.0.0.0 and " +
		"end_ip_address 255.255.255.255 exposes the database to the " +
		"entire internet. Restrict firewall rules to known client ranges."
}
func (sqlFirewallOpenLegacy) Severity() ir.Severity { return ir.SeverityHigh }

func (sqlFirewallOpenLegacy) AppliesTo(resType string) bool {
	return resType == "azurerm_sql_firewall_rule"
}

func (s sqlFirewallOpenLegacy) Check(r ir.Resource) []ir.Finding {
	return sqlFirewallOpen(s, r)
}

func sqlFirewallOpen(rule ir.Rule, r ir.Resource) []ir.Finding {
	start, _, spresent, sknown := getString(r, "start_ip_address")
	end, espan, epresent, eknown := getString(r, "end_ip_address")
	if !spresent || !sknown || !epresent || !eknown {
		return nil
	}
	if strings.TrimSpace(start) == "0.0.0.0" && strings.TrimSpace(end) == "255.255.255.255" {
		return []ir.Finding{mkFinding(rule, r, "end_ip_address", espan,
			"0.0.0.0 - 255.255.255.255", "restricted IP range")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-209: SQL Managed Instance with public endpoint
// ---------------------------------------------------------------------------

type mssqlMIPublicEndpoint struct{}

func (mssqlMIPublicEndpoint) ID() string { return "AEGIS-AZURE-209" }
func (mssqlMIPublicEndpoint) Title() string {
	return "SQL Managed Instance with public data endpoint enabled"
}
func (mssqlMIPublicEndpoint) Description() string {
	return "azurerm_mssql_managed_instance with " +
		"public_data_endpoint_enabled = true exposes the managed " +
		"instance to the internet. Keep the public endpoint disabled " +
		"and connect over private networking."
}
func (mssqlMIPublicEndpoint) Severity() ir.Severity { return ir.SeverityHigh }

func (mssqlMIPublicEndpoint) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_managed_instance"
}

func (s mssqlMIPublicEndpoint) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "public_data_endpoint_enabled")
	if !present || !known {
		return nil // default false: secure
	}
	if !en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "public_data_endpoint_enabled", span,
		"true", "public_data_endpoint_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-210: SQL Managed Instance below TLS 1.2
// ---------------------------------------------------------------------------

type mssqlMIMinTLS struct{}

func (mssqlMIMinTLS) ID() string { return "AEGIS-AZURE-210" }
func (mssqlMIMinTLS) Title() string {
	return "SQL Managed Instance below TLS 1.2"
}
func (mssqlMIMinTLS) Description() string {
	return "azurerm_mssql_managed_instance with minimum_tls_version " +
		"other than \"1.2\" permits weaker protocol versions. Enforce " +
		"TLS 1.2."
}
func (mssqlMIMinTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (mssqlMIMinTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_managed_instance"
}

func (s mssqlMIMinTLS) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "minimum_tls_version")
	if !present || !known {
		return nil
	}
	if ver == "1.2" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "minimum_tls_version", span,
		ver, "minimum_tls_version = \"1.2\"")}
}

// siteConfigString reads a string from the site_config block (tri-state).
func siteConfigString(r ir.Resource, name string) (string, ir.Span, bool, bool) {
	scs, span, present, known := getBlocks(r, "site_config")
	if !present || !known || len(scs) == 0 {
		return "", span, present, false
	}
	return blockString(scs[0], name)
}

// siteConfigBool reads a bool from the site_config block (tri-state).
func siteConfigBool(r ir.Resource, name string) (bool, ir.Span, bool, bool) {
	scs, span, present, known := getBlocks(r, "site_config")
	if !present || !known || len(scs) == 0 {
		return false, span, present, false
	}
	return blockBool(scs[0], name)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-211: App Service with FTPS allowed
// ---------------------------------------------------------------------------

type appServiceFTPS struct{}

func (appServiceFTPS) ID() string { return "AEGIS-AZURE-211" }
func (appServiceFTPS) Title() string {
	return "App Service with FTPS enabled"
}
func (appServiceFTPS) Description() string {
	return "azurerm_app_service site_config with ftps_state other than " +
		"\"Disabled\" allows FTP/S deployment, which can transmit " +
		"credentials insecurely. Set ftps_state = \"Disabled\" and " +
		"deploy via CI/CD with managed identity."
}
func (appServiceFTPS) Severity() ir.Severity { return ir.SeverityMedium }

func (appServiceFTPS) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service"
}

func (s appServiceFTPS) Check(r ir.Resource) []ir.Finding {
	return ftpsCheck(s, r)
}

func ftpsCheck(rule ir.Rule, r ir.Resource) []ir.Finding {
	st, span, present, known := siteConfigString(r, "ftps_state")
	if present && !known {
		return nil
	}
	if present && strings.EqualFold(strings.TrimSpace(st), "Disabled") {
		return nil
	}
	actual := "AllAllowed"
	if !present {
		actual = "absent (provider default: AllAllowed)"
	} else {
		actual = st
	}
	return []ir.Finding{mkFinding(rule, r, "site_config",
		evidenceSpan(span, r.Span), actual,
		"site_config { ftps_state = \"Disabled\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-212: App Service without HTTP/2
// ---------------------------------------------------------------------------

type appServiceNoHTTP2 struct{}

func (appServiceNoHTTP2) ID() string { return "AEGIS-AZURE-212" }
func (appServiceNoHTTP2) Title() string {
	return "App Service without HTTP/2"
}
func (appServiceNoHTTP2) Description() string {
	return "azurerm_app_service site_config without http2_enabled = true " +
		"serves traffic over HTTP/1.1 only. Enable HTTP/2 for modern " +
		"transport security features."
}
func (appServiceNoHTTP2) Severity() ir.Severity { return ir.SeverityLow }

func (appServiceNoHTTP2) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service"
}

func (s appServiceNoHTTP2) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalseSiteConfig(s, r, "http2_enabled",
		"site_config { http2_enabled = true }")
}

// absentInsecureFalseSiteConfig fires when a site_config bool is absent
// (default false, insecure) or explicitly false.
func absentInsecureFalseSiteConfig(rule ir.Rule, r ir.Resource, attr, expected string) []ir.Finding {
	val, span, present, known := siteConfigBool(r, attr)
	if present && !known {
		return nil
	}
	if present && val {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{mkFinding(rule, r, "site_config",
		evidenceSpan(span, r.Span), actual, expected)}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-213: App Service below TLS 1.2

func minTLSCheck(rule ir.Rule, r ir.Resource) []ir.Finding {
	ver, span, present, known := siteConfigString(r, "minimum_tls_version")
	if !present || !known {
		return nil
	}
	if ver == "1.2" {
		return nil
	}
	return []ir.Finding{mkFinding(rule, r, "site_config", evidenceSpan(span, r.Span),
		ver, "site_config { minimum_tls_version = \"1.2\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-214: App Service without IP restrictions
// ---------------------------------------------------------------------------

type appServiceNoIPRestrict struct{}

func (appServiceNoIPRestrict) ID() string { return "AEGIS-AZURE-214" }
func (appServiceNoIPRestrict) Title() string {
	return "App Service without IP restrictions"
}
func (appServiceNoIPRestrict) Description() string {
	return "azurerm_app_service site_config without ip_restriction " +
		"accepts traffic from any source IP. Restrict the app to known " +
		"callers or front it with WAF."
}
func (appServiceNoIPRestrict) Severity() ir.Severity { return ir.SeverityMedium }

func (appServiceNoIPRestrict) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service"
}

func (s appServiceNoIPRestrict) Check(r ir.Resource) []ir.Finding {
	return ipRestrictCheck(s, r)
}

func ipRestrictCheck(rule ir.Rule, r ir.Resource) []ir.Finding {
	scs, span, present, known := getBlocks(r, "site_config")
	if present && !known {
		return nil
	}
	if present {
		for _, sc := range scs {
			if hasNonEmptyBlock(sc, "ip_restriction") {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(rule, r, "site_config",
		evidenceSpan(span, r.Span), "no ip_restriction block",
		"site_config { ip_restriction { ip_address = \"<cidr>\" } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-215: App Service without client certificate mode
// ---------------------------------------------------------------------------

type appServiceNoClientCert struct{}

func (appServiceNoClientCert) ID() string { return "AEGIS-AZURE-215" }
func (appServiceNoClientCert) Title() string {
	return "App Service without client certificate requirement"
}
func (appServiceNoClientCert) Description() string {
	return "azurerm_app_service without client_cert_enabled = true " +
		"accepts requests without mutual TLS. Require client " +
		"certificates for sensitive internal applications."
}
func (appServiceNoClientCert) Severity() ir.Severity { return ir.SeverityLow }

func (appServiceNoClientCert) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service"
}

func (s appServiceNoClientCert) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "client_cert_enabled",
		"client_cert_enabled = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-216: App Service slot without HTTPS-only
// ---------------------------------------------------------------------------

type appServiceSlotNoHTTPS struct{}

func (appServiceSlotNoHTTPS) ID() string { return "AEGIS-AZURE-216" }
func (appServiceSlotNoHTTPS) Title() string {
	return "App Service deployment slot without HTTPS-only"
}
func (appServiceSlotNoHTTPS) Description() string {
	return "azurerm_app_service_slot without https_only = true serves " +
		"slot traffic over plain HTTP. Enforce HTTPS-only on every " +
		"deployment slot, not just production."
}
func (appServiceSlotNoHTTPS) Severity() ir.Severity { return ir.SeverityHigh }

func (appServiceSlotNoHTTPS) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service_slot"
}

func (s appServiceSlotNoHTTPS) Check(r ir.Resource) []ir.Finding {
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
// AEGIS-AZURE-217..219: Windows Web App family
// ---------------------------------------------------------------------------

type windowsWebAppFTPS struct{}

func (windowsWebAppFTPS) ID() string { return "AEGIS-AZURE-217" }
func (windowsWebAppFTPS) Title() string {
	return "Windows Web App with FTPS enabled"
}
func (windowsWebAppFTPS) Description() string {
	return "azurerm_windows_web_app site_config with ftps_state other " +
		"than \"Disabled\" allows FTP/S deployment. Set ftps_state = " +
		"\"Disabled\"."
}
func (windowsWebAppFTPS) Severity() ir.Severity { return ir.SeverityMedium }
func (windowsWebAppFTPS) AppliesTo(resType string) bool {
	return resType == "azurerm_windows_web_app"
}
func (s windowsWebAppFTPS) Check(r ir.Resource) []ir.Finding {
	return ftpsCheck(s, r)
}

type windowsWebAppMinTLS struct{}

func (windowsWebAppMinTLS) ID() string { return "AEGIS-AZURE-218" }
func (windowsWebAppMinTLS) Title() string {
	return "Windows Web App below TLS 1.2"
}
func (windowsWebAppMinTLS) Description() string {
	return "azurerm_windows_web_app site_config with " +
		"minimum_tls_version other than \"1.2\" permits weak protocol " +
		"versions. Enforce TLS 1.2."
}
func (windowsWebAppMinTLS) Severity() ir.Severity { return ir.SeverityHigh }
func (windowsWebAppMinTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_windows_web_app"
}
func (s windowsWebAppMinTLS) Check(r ir.Resource) []ir.Finding {
	return minTLSCheck(s, r)
}

type windowsWebAppNoIPRestrict struct{}

func (windowsWebAppNoIPRestrict) ID() string { return "AEGIS-AZURE-219" }
func (windowsWebAppNoIPRestrict) Title() string {
	return "Windows Web App without IP restrictions"
}
func (windowsWebAppNoIPRestrict) Description() string {
	return "azurerm_windows_web_app site_config without ip_restriction " +
		"accepts traffic from any source IP. Restrict the app to known " +
		"callers."
}
func (windowsWebAppNoIPRestrict) Severity() ir.Severity { return ir.SeverityMedium }
func (windowsWebAppNoIPRestrict) AppliesTo(resType string) bool {
	return resType == "azurerm_windows_web_app"
}
func (s windowsWebAppNoIPRestrict) Check(r ir.Resource) []ir.Finding {
	return ipRestrictCheck(s, r)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-220..222: Linux Web App family
// ---------------------------------------------------------------------------

type linuxWebAppFTPS struct{}

func (linuxWebAppFTPS) ID() string { return "AEGIS-AZURE-220" }
func (linuxWebAppFTPS) Title() string {
	return "Linux Web App with FTPS enabled"
}
func (linuxWebAppFTPS) Description() string {
	return "azurerm_linux_web_app site_config with ftps_state other " +
		"than \"Disabled\" allows FTP/S deployment. Set ftps_state = " +
		"\"Disabled\"."
}
func (linuxWebAppFTPS) Severity() ir.Severity { return ir.SeverityMedium }
func (linuxWebAppFTPS) AppliesTo(resType string) bool {
	return resType == "azurerm_linux_web_app"
}
func (s linuxWebAppFTPS) Check(r ir.Resource) []ir.Finding {
	return ftpsCheck(s, r)
}

type linuxWebAppMinTLS struct{}

func (linuxWebAppMinTLS) ID() string { return "AEGIS-AZURE-221" }
func (linuxWebAppMinTLS) Title() string {
	return "Linux Web App below TLS 1.2"
}
func (linuxWebAppMinTLS) Description() string {
	return "azurerm_linux_web_app site_config with " +
		"minimum_tls_version other than \"1.2\" permits weak protocol " +
		"versions. Enforce TLS 1.2."
}
func (linuxWebAppMinTLS) Severity() ir.Severity { return ir.SeverityHigh }
func (linuxWebAppMinTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_linux_web_app"
}
func (s linuxWebAppMinTLS) Check(r ir.Resource) []ir.Finding {
	return minTLSCheck(s, r)
}

type linuxWebAppNoIPRestrict struct{}

func (linuxWebAppNoIPRestrict) ID() string { return "AEGIS-AZURE-222" }
func (linuxWebAppNoIPRestrict) Title() string {
	return "Linux Web App without IP restrictions"
}
func (linuxWebAppNoIPRestrict) Description() string {
	return "azurerm_linux_web_app site_config without ip_restriction " +
		"accepts traffic from any source IP. Restrict the app to known " +
		"callers."
}
func (linuxWebAppNoIPRestrict) Severity() ir.Severity { return ir.SeverityMedium }
func (linuxWebAppNoIPRestrict) AppliesTo(resType string) bool {
	return resType == "azurerm_linux_web_app"
}
func (s linuxWebAppNoIPRestrict) Check(r ir.Resource) []ir.Finding {
	return ipRestrictCheck(s, r)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-223: App Service without VNet integration
// ---------------------------------------------------------------------------

type appServiceNoVNet struct{}

func (appServiceNoVNet) ID() string { return "AEGIS-AZURE-223" }
func (appServiceNoVNet) Title() string {
	return "App Service without virtual network integration"
}
func (appServiceNoVNet) Description() string {
	return "azurerm_app_service without virtual_network_subnet_id is " +
		"not integrated with a virtual network, so outbound traffic to " +
		"databases and Key Vault traverses public endpoints. Enable " +
		"regional VNet integration."
}
func (appServiceNoVNet) Severity() ir.Severity { return ir.SeverityMedium }

func (appServiceNoVNet) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service" ||
		resType == "azurerm_linux_web_app" ||
		resType == "azurerm_windows_web_app"
}

func (s appServiceNoVNet) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["virtual_network_subnet_id"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "virtual_network_subnet_id", r.Span,
			"absent (no VNet integration)",
			"virtual_network_subnet_id = azurerm_subnet.example.id")}
	}
	if !v.Known {
		return nil
	}
	sv, kok := v.AsString()
	if !kok || strings.TrimSpace(sv) == "" {
		return []ir.Finding{mkFinding(s, r, "virtual_network_subnet_id", v.Span,
			"empty", "virtual_network_subnet_id = azurerm_subnet.example.id")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-224: App Service slot without IP restrictions
// ---------------------------------------------------------------------------

type appServiceSlotNoIPRestrict struct{}

func (appServiceSlotNoIPRestrict) ID() string { return "AEGIS-AZURE-224" }
func (appServiceSlotNoIPRestrict) Title() string {
	return "App Service deployment slot without IP restrictions"
}
func (appServiceSlotNoIPRestrict) Description() string {
	return "azurerm_app_service_slot site_config without ip_restriction " +
		"accepts traffic from any source IP on the staging slot. " +
		"Restrict slot traffic like production."
}
func (appServiceSlotNoIPRestrict) Severity() ir.Severity { return ir.SeverityMedium }

func (appServiceSlotNoIPRestrict) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service_slot"
}

func (s appServiceSlotNoIPRestrict) Check(r ir.Resource) []ir.Finding {
	return ipRestrictCheck(s, r)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-225: SQL server without Entra ID administrator
// ---------------------------------------------------------------------------

type mssqlNoAADAdmin struct{}

func (mssqlNoAADAdmin) ID() string { return "AEGIS-AZURE-225" }
func (mssqlNoAADAdmin) Title() string {
	return "SQL server without Entra ID administrator"
}
func (mssqlNoAADAdmin) Description() string {
	return "azurerm_mssql_server without an azuread_administrator block " +
		"cannot use Entra ID authentication and relies on SQL logins. " +
		"Configure an Entra ID admin and prefer Entra-only " +
		"authentication."
}
func (mssqlNoAADAdmin) Severity() ir.Severity { return ir.SeverityMedium }

func (mssqlNoAADAdmin) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server"
}

func (s mssqlNoAADAdmin) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "azuread_administrator")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "azuread_administrator",
		evidenceSpan(span, r.Span), "absent (SQL logins only)",
		"azuread_administrator { login_username = \"...\" }")}
}
