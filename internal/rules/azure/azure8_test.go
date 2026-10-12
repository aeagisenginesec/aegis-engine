package azure

import (
	"testing"

	"aegis/internal/ir"
)

func appSvcRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_app_service", "a", attrs)
}

func TestAZURE061_AuthDisabledFires(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"auth_settings": blks(3, blk("enabled", ks("false", 4))),
	})
	mustFinding(t, runRule(appSvcNoAuth{}, r), "AEGIS-AZURE-061")
}

func TestAZURE109_AuthEnabledQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"auth_settings": blks(3, blk("enabled", ks("true", 4))),
	})
	if len(runRule(appSvcNoAuth{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE109_UnknownQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"auth_settings": blks(3, blk("enabled", ku(4))),
	})
	if len(runRule(appSvcNoAuth{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE110_NoClientCertFires verifies client certificate detection.
func TestAZURE110_NoClientCertFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoClientCert{}, appSvcRes(nil)), "AEGIS-AZURE-110")
}

func TestAZURE110_DisabledFires(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{"client_cert_enabled": kv(false, 3)})
	mustFinding(t, runRule(appSvcNoClientCert{}, r), "AEGIS-AZURE-110")
}

func TestAZURE110_EnabledQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{"client_cert_enabled": kv(true, 3)})
	if len(runRule(appSvcNoClientCert{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE111_NoDetailedErrorsFires verifies detailed error logging.
func TestAZURE111_NoDetailedErrorsFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoDetailedErr{}, appSvcRes(nil)), "AEGIS-AZURE-111")
}

func TestAZURE111_LogsBlockWithoutFlagFires(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{"logs": blks(3, blk())})
	mustFinding(t, runRule(appSvcNoDetailedErr{}, r), "AEGIS-AZURE-111")
}

func TestAZURE111_EnabledQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"logs": blks(3, blk("detailed_error_messages_enabled", kv(true, 4))),
	})
	if len(runRule(appSvcNoDetailedErr{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE112_NoFailedReqTracingFires verifies failed request tracing.
func TestAZURE112_NoFailedReqTracingFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoFailedReq{}, appSvcRes(nil)), "AEGIS-AZURE-112")
}

func TestAZURE112_EnabledQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"logs": blks(3, blk("failed_request_tracing_enabled", kv(true, 4))),
	})
	if len(runRule(appSvcNoFailedReq{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE113_FtpDefaultFires verifies FTPS restriction (strict).
func TestAZURE113_FtpDefaultFires(t *testing.T) {
	mustFinding(t, runRule(appSvcFtpNotRestrict{}, appSvcRes(nil)), "AEGIS-AZURE-113")
}

func TestAZURE113_AllAllowedFires(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"site_config": blks(3, blk("ftps_state", ks("AllAllowed", 4))),
	})
	mustFinding(t, runRule(appSvcFtpNotRestrict{}, r), "AEGIS-AZURE-113")
}

func TestAZURE113_FtpsOnlyQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"site_config": blks(3, blk("ftps_state", ks("FtpsOnly", 4))),
	})
	if len(runRule(appSvcFtpNotRestrict{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE113_DisabledQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"site_config": blks(3, blk("ftps_state", ks("Disabled", 4))),
	})
	if len(runRule(appSvcFtpNotRestrict{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE114_NoHTTPLoggingFires verifies HTTP logging detection.
func TestAZURE114_NoHTTPLoggingFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoHTTPLogging{}, appSvcRes(nil)), "AEGIS-AZURE-114")
}

func TestAZURE114_HttpLogsQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"logs": blks(3, blk("http_logs", blks(4, blk()))),
	})
	if len(runRule(appSvcNoHTTPLogging{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE114_TopLevelQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{"http_logging_enabled": kv(true, 3)})
	if len(runRule(appSvcNoHTTPLogging{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE115_NoHTTP2Fires verifies HTTP/2 detection.
func TestAZURE115_NoHTTP2Fires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoHTTP2{}, appSvcRes(nil)), "AEGIS-AZURE-115")
}

func TestAZURE115_DisabledFires(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"site_config": blks(3, blk("http2_enabled", kv(false, 4))),
	})
	mustFinding(t, runRule(appSvcNoHTTP2{}, r), "AEGIS-AZURE-115")
}

func TestAZURE115_EnabledQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"site_config": blks(3, blk("http2_enabled", kv(true, 4))),
	})
	if len(runRule(appSvcNoHTTP2{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE116_NoIdentityFires verifies system-assigned identity.
func TestAZURE116_NoIdentityFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoIdentity2{}, appSvcRes(nil)), "AEGIS-AZURE-116")
}

func TestAZURE116_UserAssignedFires(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"identity": blks(3, blk("type", ks("UserAssigned", 4))),
	})
	mustFinding(t, runRule(appSvcNoIdentity2{}, r), "AEGIS-AZURE-116")
}

func TestAZURE116_SystemAssignedQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"identity": blks(3, blk("type", ks("SystemAssigned", 4))),
	})
	if len(runRule(appSvcNoIdentity2{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE116_CombinedQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"identity": blks(3, blk("type", ks("SystemAssigned, UserAssigned", 4))),
	})
	if len(runRule(appSvcNoIdentity2{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE117_NoHealthCheckFires verifies health check path.
func TestAZURE117_NoHealthCheckFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoHealthCheck{}, appSvcRes(nil)), "AEGIS-AZURE-066")
}

func TestAZURE117_SiteConfigWithoutPathFires(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{"site_config": blks(3, blk())})
	mustFinding(t, runRule(appSvcNoHealthCheck{}, r), "AEGIS-AZURE-066")
}

func TestAZURE117_PathQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"site_config": blks(3, blk("health_check_path", ks("/health", 4))),
	})
	if len(runRule(appSvcNoHealthCheck{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// TestAZURE118_NoStorageMountFires verifies storage account block.
func TestAZURE118_NoStorageMountFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoStorageMount{}, appSvcRes(nil)), "AEGIS-AZURE-118")
}

func TestAZURE118_MountQuiet(t *testing.T) {
	r := appSvcRes(map[string]ir.Value{
		"storage_account": blks(3, blk("type", ks("AzureFiles", 4))),
	})
	if len(runRule(appSvcNoStorageMount{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
