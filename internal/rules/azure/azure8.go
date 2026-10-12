// Package azure — App Service hardening rules, round 2 (AEGIS-AZURE-109..118).
//
// Absent-attribute policy for this file (documented per the pack contract):
// these "without X" hardening rules treat an absent attribute as a finding,
// because the azurerm provider defaults are the insecure ones (auth off,
// FTPS AllAllowed, HTTP/2 off, no client certs). Present-but-unresolved
// values still yield NO finding.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure8Rules returns App Service hardening rules in ID order.
func Azure8Rules() []ir.Rule {
	return []ir.Rule{
		appSvcNoClientCert{},   // AEGIS-AZURE-110
		appSvcNoDetailedErr{},  // AEGIS-AZURE-111
		appSvcNoFailedReq{},    // AEGIS-AZURE-112
		appSvcFtpNotRestrict{}, // AEGIS-AZURE-113
		appSvcNoHTTPLogging{},  // AEGIS-AZURE-114
		appSvcNoHTTP2{},        // AEGIS-AZURE-115
		appSvcNoIdentity2{},    // AEGIS-AZURE-116
		appSvcNoStorageMount{}, // AEGIS-AZURE-118
	}
}

// appSvcTypes are the web-app resource types these rules inspect.
func appSvcTypes(resType string) bool {
	return resType == "azurerm_app_service" ||
		resType == "azurerm_linux_web_app" ||
		resType == "azurerm_windows_web_app"
}

// logsBoolEnabled reports whether any logs block (or a top-level attribute
// of the same name) has one of the named booleans set to true.
func logsBoolEnabled(r ir.Resource, block string, names ...string) bool {
	for _, n := range names {
		if v, _, p, k := getBool(r, n); p && k && v {
			return true
		}
	}
	blks, _, present, known := getBlocks(r, block)
	if !present || !known {
		return false
	}
	for _, b := range blks {
		for _, n := range names {
			if v, _, p, k := blockBool(b, n); p && k && v {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-109: App Service without authentication (strict)

// ---------------------------------------------------------------------------
// AEGIS-AZURE-110: App Service without client certificates
// ---------------------------------------------------------------------------

type appSvcNoClientCert struct{}

func (appSvcNoClientCert) ID() string { return "AEGIS-AZURE-110" }
func (appSvcNoClientCert) Title() string {
	return "App Service without client certificates"
}
func (appSvcNoClientCert) Description() string {
	return "azurerm_app_service without client_cert_enabled = true skips " +
		"mutual TLS. Require client certificates for sensitive apps."
}
func (appSvcNoClientCert) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcNoClientCert) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service"
}

func (s appSvcNoClientCert) Check(r ir.Resource) []ir.Finding {
	// Provider default is false; absent means no client certificates.
	cc, span, present, known := getBool(r, "client_cert_enabled")
	if present {
		if !known {
			return nil
		}
		if cc {
			return nil
		}
		return []ir.Finding{mkFinding(s, r, "client_cert_enabled", span,
			"false", "client_cert_enabled = true")}
	}
	return []ir.Finding{mkFinding(s, r, "client_cert_enabled",
		evidenceSpan(ir.Span{}, r.Span), "absent", "client_cert_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-111: App Service without detailed error messages
// ---------------------------------------------------------------------------

type appSvcNoDetailedErr struct{}

func (appSvcNoDetailedErr) ID() string { return "AEGIS-AZURE-111" }
func (appSvcNoDetailedErr) Title() string {
	return "App Service without detailed error messages"
}
func (appSvcNoDetailedErr) Description() string {
	return "Web app logs block without detailed error messages enabled " +
		"loses diagnostic detail for failed requests. Enable detailed " +
		"error messages in the logs configuration."
}
func (appSvcNoDetailedErr) Severity() ir.Severity { return ir.SeverityLow }

func (appSvcNoDetailedErr) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcNoDetailedErr) Check(r ir.Resource) []ir.Finding {
	if logsBoolEnabled(r, "logs", "detailed_error_messages_enabled",
		"detailed_error_logging_enabled") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "logs.detailed_error_messages_enabled",
		evidenceSpan(ir.Span{}, r.Span), "disabled or absent",
		"logs { detailed_error_messages_enabled = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-112: App Service without failed request tracing
// ---------------------------------------------------------------------------

type appSvcNoFailedReq struct{}

func (appSvcNoFailedReq) ID() string { return "AEGIS-AZURE-112" }
func (appSvcNoFailedReq) Title() string {
	return "App Service without failed request tracing"
}
func (appSvcNoFailedReq) Description() string {
	return "Web app logs block without failed_request_tracing_enabled " +
		"loses FREB traces for diagnosing failures. Enable failed request tracing."
}
func (appSvcNoFailedReq) Severity() ir.Severity { return ir.SeverityLow }

func (appSvcNoFailedReq) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcNoFailedReq) Check(r ir.Resource) []ir.Finding {
	if logsBoolEnabled(r, "logs", "failed_request_tracing_enabled") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "logs.failed_request_tracing_enabled",
		evidenceSpan(ir.Span{}, r.Span), "disabled or absent",
		"logs { failed_request_tracing_enabled = true }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-113: App Service FTP not restricted to FTPS
// ---------------------------------------------------------------------------

type appSvcFtpNotRestrict struct{}

func (appSvcFtpNotRestrict) ID() string { return "AEGIS-AZURE-113" }
func (appSvcFtpNotRestrict) Title() string {
	return "App Service with FTP enabled"
}
func (appSvcFtpNotRestrict) Description() string {
	return "Web app site_config without ftps_state = \"FtpsOnly\" (or " +
		"\"Disabled\") permits plaintext FTP deployments. The provider " +
		"default is AllAllowed. Restrict to FTPS only."
}
func (appSvcFtpNotRestrict) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcFtpNotRestrict) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcFtpNotRestrict) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present {
		// Provider default is AllAllowed: absent means FTP is enabled.
		return []ir.Finding{mkFinding(s, r, "site_config.ftps_state",
			evidenceSpan(ir.Span{}, r.Span), "absent (default AllAllowed)",
			"ftps_state = \"FtpsOnly\"")}
	}
	if !known || len(blks) == 0 {
		return nil
	}
	ftps, span, fp, fk := blockString(blks[0], "ftps_state")
	if !fp {
		return []ir.Finding{mkFinding(s, r, "site_config.ftps_state",
			evidenceSpan(ir.Span{}, r.Span), "absent (default AllAllowed)",
			"ftps_state = \"FtpsOnly\"")}
	}
	if !fk {
		return nil
	}
	if strings.EqualFold(ftps, "FtpsOnly") || strings.EqualFold(ftps, "Disabled") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "site_config.ftps_state", span,
		ftps, "ftps_state = \"FtpsOnly\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-114: App Service without HTTP logging
// ---------------------------------------------------------------------------

type appSvcNoHTTPLogging struct{}

func (appSvcNoHTTPLogging) ID() string { return "AEGIS-AZURE-114" }
func (appSvcNoHTTPLogging) Title() string {
	return "App Service without HTTP logging"
}
func (appSvcNoHTTPLogging) Description() string {
	return "Web app without HTTP request logging (logs { http_logs } or " +
		"http_logging_enabled) loses the web-server audit trail. Enable " +
		"HTTP logging to storage or the file system."
}
func (appSvcNoHTTPLogging) Severity() ir.Severity { return ir.SeverityLow }

func (appSvcNoHTTPLogging) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcNoHTTPLogging) Check(r ir.Resource) []ir.Finding {
	if logsBoolEnabled(r, "logs", "http_logging_enabled") {
		return nil
	}
	blks, _, present, known := getBlocks(r, "logs")
	if present && known {
		for _, b := range blks {
			if len(blockList(b, "http_logs")) > 0 {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "logs.http_logs",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"logs { http_logs { file_system { retention_in_days = 30 } } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-115: App Service without HTTP/2
// ---------------------------------------------------------------------------

type appSvcNoHTTP2 struct{}

func (appSvcNoHTTP2) ID() string { return "AEGIS-AZURE-115" }
func (appSvcNoHTTP2) Title() string {
	return "App Service not using latest HTTP version"
}
func (appSvcNoHTTP2) Description() string {
	return "Web app site_config without http2_enabled = true serves traffic " +
		"over HTTP/1.1. Enable HTTP/2 for the latest protocol behavior and " +
		"performance."
}
func (appSvcNoHTTP2) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcNoHTTP2) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcNoHTTP2) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "site_config")
	if !present || !known || len(blks) == 0 {
		// Provider default is false; absent means HTTP/2 is off.
		return []ir.Finding{mkFinding(s, r, "site_config.http2_enabled",
			evidenceSpan(ir.Span{}, r.Span), "absent (default false)",
			"site_config { http2_enabled = true }")}
	}
	h2, span, hp, hk := blockBool(blks[0], "http2_enabled")
	if !hp {
		return []ir.Finding{mkFinding(s, r, "site_config.http2_enabled",
			evidenceSpan(ir.Span{}, r.Span), "absent (default false)",
			"site_config { http2_enabled = true }")}
	}
	if !hk {
		return nil
	}
	if h2 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "site_config.http2_enabled", span,
		"false", "http2_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-116: App Service without system-assigned identity
// ---------------------------------------------------------------------------

type appSvcNoIdentity2 struct{}

func (appSvcNoIdentity2) ID() string { return "AEGIS-AZURE-116" }
func (appSvcNoIdentity2) Title() string {
	return "App Service without system-assigned managed identity"
}
func (appSvcNoIdentity2) Description() string {
	return "Web app identity block without type containing \"SystemAssigned\" " +
		"cannot use a system-assigned managed identity for Key Vault or " +
		"database access. Set identity { type = \"SystemAssigned\" }."
}
func (appSvcNoIdentity2) Severity() ir.Severity { return ir.SeverityMedium }

func (appSvcNoIdentity2) AppliesTo(resType string) bool { return appSvcTypes(resType) }

func (s appSvcNoIdentity2) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "identity")
	if !present {
		return []ir.Finding{mkFinding(s, r, "identity",
			evidenceSpan(ir.Span{}, r.Span), "absent",
			"identity { type = \"SystemAssigned\" }")}
	}
	if !known || len(blks) == 0 {
		return nil
	}
	for _, b := range blks {
		t, _, tp, tk := blockString(b, "type")
		if tp && !tk {
			return nil // unresolved type: cannot decide
		}
		if tp && strings.Contains(strings.ToLower(t), "systemassigned") {
			return nil
		}
	}
	return []ir.Finding{mkFinding(s, r, "identity.type",
		evidenceSpan(ir.Span{}, r.Span), "no SystemAssigned",
		"identity { type = \"SystemAssigned\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-117: App Service without health check (strict)

// ---------------------------------------------------------------------------
// AEGIS-AZURE-118: App Service without Azure Files storage mount
// ---------------------------------------------------------------------------

type appSvcNoStorageMount struct{}

func (appSvcNoStorageMount) ID() string { return "AEGIS-AZURE-118" }
func (appSvcNoStorageMount) Title() string {
	return "App Service without Azure Files storage mount"
}
func (appSvcNoStorageMount) Description() string {
	return "azurerm_app_service without a storage_account block has no " +
		"persistent Azure Files mount. Mount Azure Files for durable " +
		"shared storage across instances."
}
func (appSvcNoStorageMount) Severity() ir.Severity { return ir.SeverityLow }

func (appSvcNoStorageMount) AppliesTo(resType string) bool {
	return resType == "azurerm_app_service"
}

func (s appSvcNoStorageMount) Check(r ir.Resource) []ir.Finding {
	if _, _, present, _ := getBlocks(r, "storage_account"); present {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "storage_account",
		evidenceSpan(ir.Span{}, r.Span), "absent",
		"storage_account { name = \"...\" type = \"AzureFiles\" account_name = azurerm_storage_account.example.name share_name = \"...\" access_key = \"...\" mount_path = \"/mounts/files\" }")}
}
