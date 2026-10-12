package azure

import (
	"testing"

	"aegis/internal/ir"
)

func appRes(attrs map[string]ir.Value) ir.Resource {
	return res("azurerm_app_service", "app", attrs)
}

func siteConfig(pairs ...any) ir.Value {
	return blks(3, blk(pairs...))
}

// AEGIS-AZURE-137: IP restrictions
func TestAZURE137_AbsentSiteConfigFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoIPRestrictions{}, appRes(nil)), "AEGIS-AZURE-137")
}

func TestAZURE137_NoRestrictionsFires(t *testing.T) {
	r := appRes(map[string]ir.Value{"site_config": siteConfig("min_tls_version", ks("1.2", 4))})
	mustFinding(t, runRule(appSvcNoIPRestrictions{}, r), "AEGIS-AZURE-137")
}

func TestAZURE137_RestrictionQuiet(t *testing.T) {
	rule := blks(4, blk("ip_address", ks("203.0.113.0/24", 5)))
	r := appRes(map[string]ir.Value{"site_config": siteConfig("ip_restriction", rule)})
	if len(runRule(appSvcNoIPRestrictions{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-138: SCM restrictions
func TestAZURE138_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoSCMRestrictions{}, appRes(nil)), "AEGIS-AZURE-138")
}

func TestAZURE138_SCMRestrictionQuiet(t *testing.T) {
	rule := blks(4, blk("ip_address", ks("203.0.113.0/24", 5)))
	r := appRes(map[string]ir.Value{"site_config": siteConfig("scm_ip_restriction", rule)})
	if len(runRule(appSvcNoSCMRestrictions{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE138_UseMainQuiet(t *testing.T) {
	r := appRes(map[string]ir.Value{
		"site_config": siteConfig("scm_use_main_ip_restriction", kv(true, 4)),
	})
	if len(runRule(appSvcNoSCMRestrictions{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE138_UnknownQuiet(t *testing.T) {
	r := appRes(map[string]ir.Value{
		"site_config": siteConfig("scm_use_main_ip_restriction", ku(4)),
	})
	if len(runRule(appSvcNoSCMRestrictions{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-139: CORS wildcard
func TestAZURE139_WildcardFires(t *testing.T) {
	cors := blks(4, blk("allowed_origins", strList(5, "https://example.com", "*")))
	r := appRes(map[string]ir.Value{"site_config": siteConfig("cors", cors)})
	mustFinding(t, runRule(appSvcCORSWildcard{}, r), "AEGIS-AZURE-139")
}

func TestAZURE139_NoCorsQuiet(t *testing.T) {
	r := appRes(map[string]ir.Value{"site_config": siteConfig("min_tls_version", ks("1.2", 4))})
	if len(runRule(appSvcCORSWildcard{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE139_ScopedOriginsQuiet(t *testing.T) {
	cors := blks(4, blk("allowed_origins", strList(5, "https://example.com")))
	r := appRes(map[string]ir.Value{"site_config": siteConfig("cors", cors)})
	if len(runRule(appSvcCORSWildcard{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-140: backup
func TestAZURE140_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoBackup{}, appRes(nil)), "AEGIS-AZURE-140")
}

func TestAZURE140_PresentQuiet(t *testing.T) {
	r := appRes(map[string]ir.Value{"backup": blks(3, blk("name", ks("b", 4)))})
	if len(runRule(appSvcNoBackup{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-141: application logs
func TestAZURE141_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(appSvcNoAppLogs{}, appRes(nil)), "AEGIS-AZURE-141")
}

func TestAZURE141_PresentQuiet(t *testing.T) {
	applogs := blks(4, blk("file_system_level", ks("Warning", 5)))
	r := appRes(map[string]ir.Value{"logs": blks(3, blk("application_logs", applogs))})
	if len(runRule(appSvcNoAppLogs{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-142: allow-all IP rule
func TestAZURE142_AllowAllFires(t *testing.T) {
	rule := blks(4, blk(
		"ip_address", ks("0.0.0.0/0", 5),
		"action", ks("Allow", 6),
	))
	r := appRes(map[string]ir.Value{"site_config": siteConfig("ip_restriction", rule)})
	mustFinding(t, runRule(appSvcAllowAllIPRule{}, r), "AEGIS-AZURE-142")
}

func TestAZURE142_NoSiteConfigQuiet(t *testing.T) {
	// No restrictions at all is AEGIS-AZURE-137's finding, not this rule's.
	if len(runRule(appSvcAllowAllIPRule{}, appRes(nil))) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE142_DenyAllQuiet(t *testing.T) {
	rule := blks(4, blk(
		"ip_address", ks("0.0.0.0/0", 5),
		"action", ks("Deny", 6),
	))
	r := appRes(map[string]ir.Value{"site_config": siteConfig("ip_restriction", rule)})
	if len(runRule(appSvcAllowAllIPRule{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// AEGIS-AZURE-143: CORS credentials
func TestAZURE143_CredentialsFires(t *testing.T) {
	cors := blks(4, blk("support_credentials", kv(true, 5)))
	r := appRes(map[string]ir.Value{"site_config": siteConfig("cors", cors)})
	mustFinding(t, runRule(appSvcCORSCredentials{}, r), "AEGIS-AZURE-143")
}

func TestAZURE143_NoCredentialsQuiet(t *testing.T) {
	cors := blks(4, blk("support_credentials", kv(false, 5)))
	r := appRes(map[string]ir.Value{"site_config": siteConfig("cors", cors)})
	if len(runRule(appSvcCORSCredentials{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func TestAZURE143_NoCorsQuiet(t *testing.T) {
	if len(runRule(appSvcCORSCredentials{}, appRes(nil))) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// Azure11Rules returns all 7 in ID order.
func TestAzure11RulesInIDOrder(t *testing.T) {
	rules := Azure11Rules()
	if len(rules) != 7 {
		t.Fatalf("expected 7 rules, got %d", len(rules))
	}
	if rules[0].ID() != "AEGIS-AZURE-137" || rules[6].ID() != "AEGIS-AZURE-143" {
		t.Fatalf("ID order broken: %s .. %s", rules[0].ID(), rules[6].ID())
	}
}
