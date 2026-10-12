package aws

import (
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-825
// ---------------------------------------------------------------------------

func TestCloudfrontLegacyOAI_FiresOnOAI(t *testing.T) {
	r := res("aws_cloudfront_distribution", "x",
		map[string]ir.Value{"origin": blks(2,
			blk("s3_origin_config", blks(3,
				blk("origin_access_identity", ks("origin-access-identity/cloudfront/ABC", 4)))))})
	if f := runRule(cloudfrontLegacyOAI{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestCloudfrontLegacyOAI_PassesWithOAC(t *testing.T) {
	r := res("aws_cloudfront_distribution", "x",
		map[string]ir.Value{"origin": blks(2,
			blk("origin_access_control_id", ks("abc123", 3)))})
	if f := runRule(cloudfrontLegacyOAI{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestCloudfrontLegacyOAI_UnknownOAINoFinding(t *testing.T) {
	r := res("aws_cloudfront_distribution", "x",
		map[string]ir.Value{"origin": blks(2,
			blk("s3_origin_config", blks(3,
				blk("origin_access_identity", ku(4)))))})
	if f := runRule(cloudfrontLegacyOAI{}, r); len(f) != 0 {
		t.Fatalf("expected no findings on unknown, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-826
// ---------------------------------------------------------------------------

func TestCloudfrontNoRespHeaders_FiresWhenAbsent(t *testing.T) {
	r := res("aws_cloudfront_distribution", "x", map[string]ir.Value{})
	if f := runRule(cloudfrontNoRespHeaders{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestCloudfrontNoRespHeaders_PassesWithPolicy(t *testing.T) {
	r := res("aws_cloudfront_distribution", "x",
		map[string]ir.Value{"response_headers_policy_id": ks("67f7725c-6f97-4210-82c7-51e944267ff6", 2)})
	if f := runRule(cloudfrontNoRespHeaders{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-827
// ---------------------------------------------------------------------------

func TestCloudfrontPriceClassAll_FiresOnAll(t *testing.T) {
	r := res("aws_cloudfront_distribution", "x",
		map[string]ir.Value{"price_class": ks("PriceClass_All", 2)})
	if f := runRule(cloudfrontPriceClassAll{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestCloudfrontPriceClassAll_PassesOn200(t *testing.T) {
	r := res("aws_cloudfront_distribution", "x",
		map[string]ir.Value{"price_class": ks("PriceClass_200", 2)})
	if f := runRule(cloudfrontPriceClassAll{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-828
// ---------------------------------------------------------------------------

func TestCloudfrontStaging_FiresWhenTrue(t *testing.T) {
	r := res("aws_cloudfront_distribution", "x",
		map[string]ir.Value{"staging": kv(true, 2)})
	if f := runRule(cloudfrontStaging{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestCloudfrontStaging_PassesWhenAbsent(t *testing.T) {
	r := res("aws_cloudfront_distribution", "x", map[string]ir.Value{})
	if f := runRule(cloudfrontStaging{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-829
// ---------------------------------------------------------------------------

func TestApigwV2CorsWildcard_FiresOnStar(t *testing.T) {
	r := res("aws_api_gatewayv2_api", "x",
		map[string]ir.Value{"cors_configuration": blks(2,
			blk("allow_origins", strList(3, "*")))})
	if f := runRule(apigwV2CorsWildcard{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestApigwV2CorsWildcard_PassesOnSpecificOrigin(t *testing.T) {
	r := res("aws_api_gatewayv2_api", "x",
		map[string]ir.Value{"cors_configuration": blks(2,
			blk("allow_origins", strList(3, "https://app.example.com")))})
	if f := runRule(apigwV2CorsWildcard{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-830
// ---------------------------------------------------------------------------

func TestApigwV2NoAccessLogs_FiresWhenAbsent(t *testing.T) {
	r := res("aws_api_gatewayv2_stage", "x", map[string]ir.Value{})
	if f := runRule(apigwV2NoAccessLogs{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestApigwV2NoAccessLogs_PassesWithSettings(t *testing.T) {
	r := res("aws_api_gatewayv2_stage", "x",
		map[string]ir.Value{"access_log_settings": blks(2, blk("destination_arn", ks("arn:aws:logs:..", 3)))})
	if f := runRule(apigwV2NoAccessLogs{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-831
// ---------------------------------------------------------------------------

func TestApigwV2RouteNoAuth_FiresOnNone(t *testing.T) {
	r := res("aws_api_gatewayv2_route", "x",
		map[string]ir.Value{"authorization_type": ks("NONE", 2)})
	if f := runRule(apigwV2RouteNoAuth{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestApigwV2RouteNoAuth_FiresWhenAbsent(t *testing.T) {
	r := res("aws_api_gatewayv2_route", "x", map[string]ir.Value{})
	if f := runRule(apigwV2RouteNoAuth{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestApigwV2RouteNoAuth_PassesOnJWT(t *testing.T) {
	r := res("aws_api_gatewayv2_route", "x",
		map[string]ir.Value{"authorization_type": ks("JWT", 2)})
	if f := runRule(apigwV2RouteNoAuth{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-832
// ---------------------------------------------------------------------------

func TestApigwV2DomainWeakTLS_FiresOnTLS10(t *testing.T) {
	r := res("aws_apigatewayv2_domain_name", "x",
		map[string]ir.Value{"domain_name_configuration": blks(2,
			blk("security_policy", ks("TLS_1_0", 3)))})
	if f := runRule(apigwV2DomainWeakTLS{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestApigwV2DomainWeakTLS_PassesOnTLS12(t *testing.T) {
	r := res("aws_apigatewayv2_domain_name", "x",
		map[string]ir.Value{"domain_name_configuration": blks(2,
			blk("security_policy", ks("TLS_1_2", 3)))})
	if f := runRule(apigwV2DomainWeakTLS{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-833
// ---------------------------------------------------------------------------

func TestRoute53ZoneForceDestroy_FiresWhenTrue(t *testing.T) {
	r := res("aws_route53_zone", "x",
		map[string]ir.Value{"force_destroy": kv(true, 2)})
	if f := runRule(route53ZoneForceDestroy{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestRoute53ZoneForceDestroy_PassesWhenAbsent(t *testing.T) {
	r := res("aws_route53_zone", "x", map[string]ir.Value{})
	if f := runRule(route53ZoneForceDestroy{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-834
// ---------------------------------------------------------------------------

func TestBackupVaultLockShortRet_FiresBelowSeven(t *testing.T) {
	r := res("aws_backup_vault_lock_configuration", "x",
		map[string]ir.Value{"min_retention_days": num(1, 2)})
	if f := runRule(backupVaultLockShortRet{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestBackupVaultLockShortRet_PassesAtSeven(t *testing.T) {
	r := res("aws_backup_vault_lock_configuration", "x",
		map[string]ir.Value{"min_retention_days": num(30, 2)})
	if f := runRule(backupVaultLockShortRet{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestBackupVaultLockShortRet_UnknownNoFinding(t *testing.T) {
	r := res("aws_backup_vault_lock_configuration", "x",
		map[string]ir.Value{"min_retention_days": ku(2)})
	if f := runRule(backupVaultLockShortRet{}, r); len(f) != 0 {
		t.Fatalf("expected no findings on unknown, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-835
// ---------------------------------------------------------------------------

func TestBackupPlanNoCopyAction_FiresWithoutCopy(t *testing.T) {
	r := res("aws_backup_plan", "x",
		map[string]ir.Value{"rule": blks(2, blk("rule_name", ks("daily", 3)))})
	if f := runRule(backupPlanNoCopyAction{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestBackupPlanNoCopyAction_PassesWithCopy(t *testing.T) {
	r := res("aws_backup_plan", "x",
		map[string]ir.Value{"rule": blks(2,
			blk("rule_name", ks("daily", 3),
				"copy_action", blks(4, blk("destination_vault_arn", ks("arn:aws:backup:..", 5)))))})
	if f := runRule(backupPlanNoCopyAction{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestBackupPlanNoCopyAction_UnknownCopyNoFinding(t *testing.T) {
	r := res("aws_backup_plan", "x",
		map[string]ir.Value{"rule": blks(2, blk("copy_action", ku(3)))})
	if f := runRule(backupPlanNoCopyAction{}, r); len(f) != 0 {
		t.Fatalf("expected no findings on unknown, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-836 (cross-resource)
// ---------------------------------------------------------------------------

func TestBackupVaultNoLock_FiresWithoutLockConfig(t *testing.T) {
	vault := res("aws_backup_vault", "main",
		map[string]ir.Value{"name": ks("main", 2)})
	f := backupVaultNoLock{}.CheckAll([]ir.Resource{vault})
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestBackupVaultNoLock_PassesWithLockConfig(t *testing.T) {
	vault := res("aws_backup_vault", "main",
		map[string]ir.Value{"name": ks("main", 2)})
	lock := res("aws_backup_vault_lock_configuration", "main",
		map[string]ir.Value{"backup_vault_name": ks("main", 2)})
	f := backupVaultNoLock{}.CheckAll([]ir.Resource{vault, lock})
	if len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestBackupVaultNoLock_UncertainLinkNoFinding(t *testing.T) {
	vault := res("aws_backup_vault", "main",
		map[string]ir.Value{"name": ks("main", 2)})
	lock := res("aws_backup_vault_lock_configuration", "main",
		map[string]ir.Value{"backup_vault_name": ku(2)})
	f := backupVaultNoLock{}.CheckAll([]ir.Resource{vault, lock})
	if len(f) != 0 {
		t.Fatalf("expected no findings on uncertain link, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-837
// ---------------------------------------------------------------------------

func TestOrganizationsFeatureSet_FiresOnBillingOnly(t *testing.T) {
	r := res("aws_organizations_organization", "x",
		map[string]ir.Value{"feature_set": ks("CONSOLIDATED_BILLING", 2)})
	if f := runRule(organizationsFeatureSet{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestOrganizationsFeatureSet_PassesOnAll(t *testing.T) {
	for _, cfg := range []map[string]ir.Value{
		{},
		{"feature_set": ks("ALL", 2)},
	} {
		r := res("aws_organizations_organization", "x", cfg)
		if f := runRule(organizationsFeatureSet{}, r); len(f) != 0 {
			t.Fatalf("expected no findings for %v, got %d", cfg, len(f))
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-838
// ---------------------------------------------------------------------------

func TestOrgUnitNoName_FiresWhenAbsent(t *testing.T) {
	r := res("aws_organizations_organizational_unit", "x", map[string]ir.Value{})
	if f := runRule(orgUnitNoName{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestOrgUnitNoName_PassesWithName(t *testing.T) {
	r := res("aws_organizations_organizational_unit", "x",
		map[string]ir.Value{"name": ks("production", 2)})
	if f := runRule(orgUnitNoName{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-839
// ---------------------------------------------------------------------------

func TestAcmNoTransparencyLogging_FiresOnDisabled(t *testing.T) {
	r := res("aws_acm_certificate", "x",
		map[string]ir.Value{"options": blks(2,
			blk("certificate_transparency_logging_preference", ks("DISABLED", 3)))})
	if f := runRule(acmNoTransparencyLogging{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestAcmNoTransparencyLogging_PassesWhenEnabled(t *testing.T) {
	for _, cfg := range []map[string]ir.Value{
		{},
		{"options": blks(2, blk("certificate_transparency_logging_preference", ks("ENABLED", 3)))},
	} {
		r := res("aws_acm_certificate", "x", cfg)
		if f := runRule(acmNoTransparencyLogging{}, r); len(f) != 0 {
			t.Fatalf("expected no findings for %v, got %d", cfg, len(f))
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-840
// ---------------------------------------------------------------------------

func TestLBTargetGroupHTTP_FiresOnHTTP(t *testing.T) {
	r := res("aws_lb_target_group", "x",
		map[string]ir.Value{"protocol": ks("HTTP", 2)})
	if f := runRule(lbTargetGroupHTTP{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestLBTargetGroupHTTP_PassesOnHTTPS(t *testing.T) {
	r := res("aws_lb_target_group", "x",
		map[string]ir.Value{"protocol": ks("HTTPS", 2)})
	if f := runRule(lbTargetGroupHTTP{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-841
// ---------------------------------------------------------------------------

func TestLBTargetGroupHCHTTP_FiresOnHTTP(t *testing.T) {
	r := res("aws_lb_target_group", "x",
		map[string]ir.Value{"health_check": blks(2, blk("protocol", ks("HTTP", 3)))})
	if f := runRule(lbTargetGroupHCHTTP{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestLBTargetGroupHCHTTP_PassesWhenAbsent(t *testing.T) {
	r := res("aws_lb_target_group", "x", map[string]ir.Value{})
	if f := runRule(lbTargetGroupHCHTTP{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-842
// ---------------------------------------------------------------------------

func TestALBListenerOldSSLPolicy_FiresOn2016(t *testing.T) {
	r := res("aws_alb_listener", "x",
		map[string]ir.Value{"ssl_policy": ks("ELBSecurityPolicy-2016-08", 2)})
	if f := runRule(albListenerOldSSLPolicy{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestALBListenerOldSSLPolicy_PassesOnModern(t *testing.T) {
	for _, cfg := range []map[string]ir.Value{
		{},
		{"ssl_policy": ks("ELBSecurityPolicy-TLS13-1-2-2021-06", 2)},
	} {
		r := res("aws_lb_listener", "x", cfg)
		if f := runRule(albListenerOldSSLPolicy{}, r); len(f) != 0 {
			t.Fatalf("expected no findings for %v, got %d", cfg, len(f))
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-843
// ---------------------------------------------------------------------------

func TestApigwAccountNoCWRole_FiresWhenAbsent(t *testing.T) {
	r := res("aws_api_gateway_account", "x", map[string]ir.Value{})
	if f := runRule(apigwAccountNoCWRole{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestApigwAccountNoCWRole_PassesWithRole(t *testing.T) {
	r := res("aws_api_gateway_account", "x",
		map[string]ir.Value{"cloudwatch_role_arn": ks("arn:aws:iam::1:role/apigw", 2)})
	if f := runRule(apigwAccountNoCWRole{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-844
// ---------------------------------------------------------------------------

func TestApigwMethodNoValidator_FiresWhenAbsent(t *testing.T) {
	r := res("aws_api_gateway_method", "x", map[string]ir.Value{})
	if f := runRule(apigwMethodNoValidator{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestApigwMethodNoValidator_PassesWithValidator(t *testing.T) {
	r := res("aws_api_gateway_method", "x",
		map[string]ir.Value{"request_validator_id": ks("abc123", 2)})
	if f := runRule(apigwMethodNoValidator{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-845
// ---------------------------------------------------------------------------

func TestApigwUsagePlanNoThrottle_FiresWhenAbsent(t *testing.T) {
	r := res("aws_api_gateway_usage_plan", "x", map[string]ir.Value{})
	if f := runRule(apigwUsagePlanNoThrottle{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestApigwUsagePlanNoThrottle_PassesWithSettings(t *testing.T) {
	r := res("aws_api_gateway_usage_plan", "x",
		map[string]ir.Value{"throttle_settings": blks(2, blk("burst_limit", num(100, 3)))})
	if f := runRule(apigwUsagePlanNoThrottle{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-846
// ---------------------------------------------------------------------------

func TestRoute53HealthCheckDisabled_FiresWhenTrue(t *testing.T) {
	r := res("aws_route53_health_check", "x",
		map[string]ir.Value{"disabled": kv(true, 2)})
	if f := runRule(route53HealthCheckDisabled{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestRoute53HealthCheckDisabled_PassesWhenAbsent(t *testing.T) {
	r := res("aws_route53_health_check", "x", map[string]ir.Value{})
	if f := runRule(route53HealthCheckDisabled{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-847
// ---------------------------------------------------------------------------

func TestDLMPolicyDisabled_FiresOnDisabled(t *testing.T) {
	r := res("aws_dlm_lifecycle_policy", "x",
		map[string]ir.Value{"state": ks("DISABLED", 2)})
	if f := runRule(dlmPolicyDisabled{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestDLMPolicyDisabled_PassesOnEnabled(t *testing.T) {
	r := res("aws_dlm_lifecycle_policy", "x",
		map[string]ir.Value{"state": ks("ENABLED", 2)})
	if f := runRule(dlmPolicyDisabled{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-848
// ---------------------------------------------------------------------------

func TestVPNStaticRoutesOnly_FiresWhenTrue(t *testing.T) {
	r := res("aws_vpn_connection", "x",
		map[string]ir.Value{"static_routes_only": kv(true, 2)})
	if f := runRule(vpnStaticRoutesOnly{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestVPNStaticRoutesOnly_PassesWhenAbsent(t *testing.T) {
	r := res("aws_vpn_connection", "x", map[string]ir.Value{})
	if f := runRule(vpnStaticRoutesOnly{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-849
// ---------------------------------------------------------------------------

func TestTransferServerFTP_FiresOnFTP(t *testing.T) {
	r := res("aws_transfer_server", "x",
		map[string]ir.Value{"protocols": strList(2, "SFTP", "FTP")})
	if f := runRule(transferServerFTP{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestTransferServerFTP_PassesOnSFTPOnly(t *testing.T) {
	r := res("aws_transfer_server", "x",
		map[string]ir.Value{"protocols": strList(2, "SFTP")})
	if f := runRule(transferServerFTP{}, r); len(f) != 0 {
		t.Fatalf("expected no findings, got %d", len(f))
	}
}

func TestTransferServerFTP_UnknownEntryNoFinding(t *testing.T) {
	r := res("aws_transfer_server", "x",
		map[string]ir.Value{"protocols": ir.Value{Raw: []ir.Value{ku(2)}, Known: true, Span: spanAt(2)}})
	if f := runRule(transferServerFTP{}, r); len(f) != 0 {
		t.Fatalf("expected no findings on unknown, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// Registration sanity: all 25 rules present, IDs unique and ordered.
// ---------------------------------------------------------------------------

func TestEdgeDeepRules_AllIDs(t *testing.T) {
	rules := EdgeDeepRules()
	if len(rules) != 25 {
		t.Fatalf("expected 25 rules, got %d", len(rules))
	}
	seen := map[string]bool{}
	prev := ""
	for _, r := range rules {
		id := r.ID()
		if seen[id] {
			t.Fatalf("duplicate rule ID %s", id)
		}
		seen[id] = true
		if prev != "" && id <= prev {
			t.Fatalf("rules not in ID order: %s after %s", prev, id)
		}
		prev = id
	}
	for _, w := range []string{"AEGIS-AWS-825", "AEGIS-AWS-849"} {
		if !seen[w] {
			t.Fatalf("missing rule %s", w)
		}
	}
}
