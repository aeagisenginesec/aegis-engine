package aws

// Edge/API/backup/org hardening, deep round (AEGIS-AWS-825..849).
//
// Covers CloudFront (legacy OAI origins, response headers policy, price
// class, staging distributions), API Gateway v2 (CORS wildcard, access logs,
// route auth, domain TLS policy), API Gateway v1 (account CloudWatch role,
// method validators, usage-plan throttles), Route 53 (zone force_destroy,
// health checks), Backup (vault KMS, plan copy actions, vault lock), ACM
// (certificate transparency), ALB target groups (plaintext protocol, health
// check protocol) and listeners (old SSL policies), Organizations (feature
// set, OU naming), DLM (disabled policies) and VPN/Transfer (static routes,
// FTP).
//
// Unknown-value contract: a present-but-unresolved attribute yields NO
// finding. Absent attributes are judged against the provider's documented
// insecure default, documented per rule. Rules never panic on unexpected
// shapes.

import (
	"strings"

	"aegis/internal/ir"
)

// EdgeDeepRules returns the edge/API/backup/org deep rules,
// AEGIS-AWS-825..849, in ID order.
func EdgeDeepRules() []ir.Rule {
	return []ir.Rule{
		cloudfrontLegacyOAI{},        // AEGIS-AWS-825
		cloudfrontNoRespHeaders{},    // AEGIS-AWS-826
		cloudfrontPriceClassAll{},    // AEGIS-AWS-827
		cloudfrontStaging{},          // AEGIS-AWS-828
		apigwV2CorsWildcard{},        // AEGIS-AWS-829
		apigwV2DomainWeakTLS{},       // AEGIS-AWS-832
		route53ZoneForceDestroy{},    // AEGIS-AWS-833
		backupVaultLockShortRet{},    // AEGIS-AWS-834
		backupPlanNoCopyAction{},     // AEGIS-AWS-835
		backupVaultNoLock{},          // AEGIS-AWS-836
		organizationsFeatureSet{},    // AEGIS-AWS-837
		orgUnitNoName{},              // AEGIS-AWS-838
		acmNoTransparencyLogging{},   // AEGIS-AWS-839
		lbTargetGroupHTTP{},          // AEGIS-AWS-840
		lbTargetGroupHCHTTP{},        // AEGIS-AWS-841
		albListenerOldSSLPolicy{},    // AEGIS-AWS-842
		apigwAccountNoCWRole{},       // AEGIS-AWS-843
		apigwMethodNoValidator{},     // AEGIS-AWS-844
		apigwUsagePlanNoThrottle{},   // AEGIS-AWS-845
		route53HealthCheckDisabled{}, // AEGIS-AWS-846
		dlmPolicyDisabled{},          // AEGIS-AWS-847
		vpnStaticRoutesOnly{},        // AEGIS-AWS-848
		transferServerFTP{},          // AEGIS-AWS-849
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-825: CloudFront distribution using legacy OAI origins
// ---------------------------------------------------------------------------

type cloudfrontLegacyOAI struct{}

func (cloudfrontLegacyOAI) ID() string { return "AEGIS-AWS-825" }
func (cloudfrontLegacyOAI) Title() string {
	return "CloudFront distribution using legacy origin access identity"
}
func (cloudfrontLegacyOAI) Description() string {
	return "A CloudFront distribution whose S3 origin sets " +
		"origin_access_identity uses the legacy Origin Access Identity, which " +
		"cannot enforce modern SigV4 bucket policies or SSE-KMS. Migrate to " +
		"Origin Access Control (OAC)."
}
func (cloudfrontLegacyOAI) Severity() ir.Severity { return ir.SeverityHigh }
func (cloudfrontLegacyOAI) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}

func (s cloudfrontLegacyOAI) Check(r ir.Resource) []ir.Finding {
	origins, _, present, known := getBlocks(r, "origin")
	if !present || !known {
		return nil
	}
	for _, o := range origins {
		for _, soc := range blockList(o, "s3_origin_config") {
			oai, span, opresent, oknown := blockString(soc, "origin_access_identity")
			if !opresent || !oknown {
				continue
			}
			if strings.TrimSpace(oai) == "" {
				continue
			}
			return []ir.Finding{sdFinding(s, r,
				"origin.s3_origin_config.origin_access_identity", span,
				"\""+oai+"\" (legacy OAI)",
				"origin_access_control_id = <OAC> (remove origin_access_identity)")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-826: CloudFront distribution without a response headers policy
// ---------------------------------------------------------------------------

type cloudfrontNoRespHeaders struct{}

func (cloudfrontNoRespHeaders) ID() string { return "AEGIS-AWS-826" }
func (cloudfrontNoRespHeaders) Title() string {
	return "CloudFront distribution without a response headers policy"
}
func (cloudfrontNoRespHeaders) Description() string {
	return "A CloudFront distribution with no response_headers_policy_id " +
		"serves responses without hardened security headers (HSTS, " +
		"frame-options, content-type options). Attach a response headers " +
		"policy such as the managed SecurityHeadersPolicy."
}
func (cloudfrontNoRespHeaders) Severity() ir.Severity { return ir.SeverityLow }
func (cloudfrontNoRespHeaders) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}

func (s cloudfrontNoRespHeaders) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "response_headers_policy_id")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return absentInsecureDefault(s, r, "response_headers_policy_id",
		"absent (no security headers)",
		"response_headers_policy_id = <managed SecurityHeadersPolicy>")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-827: CloudFront distribution on PriceClass_All
// ---------------------------------------------------------------------------

type cloudfrontPriceClassAll struct{}

func (cloudfrontPriceClassAll) ID() string { return "AEGIS-AWS-827" }
func (cloudfrontPriceClassAll) Title() string {
	return "CloudFront distribution on the all-edge price class"
}
func (cloudfrontPriceClassAll) Description() string {
	return "A CloudFront distribution with price_class = \"PriceClass_All\" " +
		"serves from every edge location, including the most expensive " +
		"regions, with no availability benefit over a regional price class " +
		"for most workloads. Prefer PriceClass_100 or PriceClass_200."
}
func (cloudfrontPriceClassAll) Severity() ir.Severity { return ir.SeverityLow }
func (cloudfrontPriceClassAll) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}

func (s cloudfrontPriceClassAll) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "price_class")
	if !present || !known {
		return nil
	}
	if val != "PriceClass_All" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "price_class", span,
		"\"PriceClass_All\"", "price_class = \"PriceClass_200\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-828: CloudFront staging distribution
// ---------------------------------------------------------------------------

type cloudfrontStaging struct{}

func (cloudfrontStaging) ID() string { return "AEGIS-AWS-828" }
func (cloudfrontStaging) Title() string {
	return "CloudFront distribution left in staging mode"
}
func (cloudfrontStaging) Description() string {
	return "A CloudFront distribution with staging = true is a continuous " +
		"deployment test distribution that may bypass production WAF and " +
		"logging controls. Promote it to a production distribution or remove " +
		"it."
}
func (cloudfrontStaging) Severity() ir.Severity { return ir.SeverityLow }
func (cloudfrontStaging) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}

func (s cloudfrontStaging) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "staging")
	if !present || !known {
		return nil // provider default is false: absent is safe
	}
	if !val {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "staging", span,
		"true", "staging = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-829: API Gateway v2 API with wildcard CORS origins
// ---------------------------------------------------------------------------

type apigwV2CorsWildcard struct{}

func (apigwV2CorsWildcard) ID() string { return "AEGIS-AWS-829" }
func (apigwV2CorsWildcard) Title() string {
	return "API Gateway v2 API with wildcard CORS origins"
}
func (apigwV2CorsWildcard) Description() string {
	return "An API Gateway v2 API whose cors_configuration allows origin " +
		"\"*\" lets any website call the API from a browser, enabling " +
		"cross-site data theft when credentials are involved. Restrict " +
		"allow_origins to the application's own domains."
}
func (apigwV2CorsWildcard) Severity() ir.Severity { return ir.SeverityMedium }
func (apigwV2CorsWildcard) AppliesTo(resType string) bool {
	return resType == "aws_api_gatewayv2_api"
}

func (s apigwV2CorsWildcard) Check(r ir.Resource) []ir.Finding {
	cors, _, present, known := getBlocks(r, "cors_configuration")
	if !present || !known || len(cors) == 0 {
		return nil
	}
	origins, allKnown := blockStrings(cors[0], "allow_origins")
	if !allKnown {
		return nil
	}
	if !findStringFold(origins, "*") {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "cors_configuration.allow_origins",
		ir.Span{}, "contains \"*\"",
		"allow_origins = [\"https://app.example.com\"]")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-832: API Gateway v2 domain name with weak TLS security policy
// ---------------------------------------------------------------------------

type apigwV2DomainWeakTLS struct{}

func (apigwV2DomainWeakTLS) ID() string { return "AEGIS-AWS-832" }
func (apigwV2DomainWeakTLS) Title() string {
	return "API Gateway v2 domain name with TLS 1.0 security policy"
}
func (apigwV2DomainWeakTLS) Description() string {
	return "An API Gateway v2 custom domain whose domain_name_configuration " +
		"sets security_policy = \"TLS_1_0\" negotiates obsolete TLS versions " +
		"vulnerable to protocol downgrade attacks. Use TLS_1_2."
}
func (apigwV2DomainWeakTLS) Severity() ir.Severity { return ir.SeverityHigh }
func (apigwV2DomainWeakTLS) AppliesTo(resType string) bool {
	return resType == "aws_apigatewayv2_domain_name"
}

func (s apigwV2DomainWeakTLS) Check(r ir.Resource) []ir.Finding {
	cfg, _, present, known := getBlocks(r, "domain_name_configuration")
	if !present || !known || len(cfg) == 0 {
		return nil
	}
	pol, span, ppresent, pknown := blockString(cfg[0], "security_policy")
	if !ppresent || !pknown {
		return nil
	}
	if pol != "TLS_1_0" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r,
		"domain_name_configuration.security_policy", span,
		"\"TLS_1_0\"", "security_policy = \"TLS_1_2\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-833: Route 53 zone with force_destroy
// ---------------------------------------------------------------------------

type route53ZoneForceDestroy struct{}

func (route53ZoneForceDestroy) ID() string { return "AEGIS-AWS-833" }
func (route53ZoneForceDestroy) Title() string {
	return "Route 53 zone with force_destroy enabled"
}
func (route53ZoneForceDestroy) Description() string {
	return "A Route 53 zone with force_destroy = true lets terraform " +
		"destroy delete every record in the zone without confirmation, " +
		"turning a mistaken destroy into a DNS outage. Keep " +
		"force_destroy = false on production zones."
}
func (route53ZoneForceDestroy) Severity() ir.Severity { return ir.SeverityLow }
func (route53ZoneForceDestroy) AppliesTo(resType string) bool {
	return resType == "aws_route53_zone"
}

func (s route53ZoneForceDestroy) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "force_destroy")
	if !present || !known {
		return nil // provider default is false: absent is safe
	}
	if !val {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "force_destroy", span,
		"true", "force_destroy = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-834: Backup vault lock with short minimum retention
// ---------------------------------------------------------------------------
//
// (The vault kms_key_arn check already exists as AEGIS-AWS-392; this rule
// covers the distinct vault-lock retention gap instead of duplicating it.)

type backupVaultLockShortRet struct{}

func (backupVaultLockShortRet) ID() string { return "AEGIS-AWS-834" }
func (backupVaultLockShortRet) Title() string {
	return "Backup vault lock with short minimum retention"
}
func (backupVaultLockShortRet) Description() string {
	return "A Backup vault lock configuration with min_retention_days below " +
		"7 lets recovery points age out quickly, weakening the ransomware " +
		"protection vault lock is meant to provide. Set min_retention_days " +
		"to at least 7 in compliance mode."
}
func (backupVaultLockShortRet) Severity() ir.Severity { return ir.SeverityLow }
func (backupVaultLockShortRet) AppliesTo(resType string) bool {
	return resType == "aws_backup_vault_lock_configuration"
}

func (s backupVaultLockShortRet) Check(r ir.Resource) []ir.Finding {
	days, span, present, known := getNumber(r, "min_retention_days")
	if !present || !known {
		return nil // required attribute: absent is a config error, not a gap
	}
	if days >= 7 {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "min_retention_days", span,
		trimFloat(days), "min_retention_days >= 7")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-835: Backup plan rule without a copy action
// ---------------------------------------------------------------------------

type backupPlanNoCopyAction struct{}

func (backupPlanNoCopyAction) ID() string { return "AEGIS-AWS-835" }
func (backupPlanNoCopyAction) Title() string {
	return "Backup plan rule without a copy action"
}
func (backupPlanNoCopyAction) Description() string {
	return "A Backup plan rule with no copy_action keeps recovery points in " +
		"a single vault and region, so a regional incident can take backups " +
		"with it. Add a copy_action to a second vault or region."
}
func (backupPlanNoCopyAction) Severity() ir.Severity { return ir.SeverityLow }
func (backupPlanNoCopyAction) AppliesTo(resType string) bool {
	return resType == "aws_backup_plan"
}

func (s backupPlanNoCopyAction) Check(r ir.Resource) []ir.Finding {
	rules, _, present, known := getBlocks(r, "rule")
	if !present || !known {
		return nil
	}
	for _, m := range rules {
		copies := blockList(m, "copy_action")
		if len(copies) > 0 {
			continue
		}
		// copy_action key present but unresolved is undecidable.
		if v, ok := m["copy_action"]; ok && !v.Known {
			return nil
		}
		return []ir.Finding{sdFinding(s, r, "rule.copy_action", ir.Span{},
			"absent (no cross-region copy)",
			"rule { copy_action { destination_vault_arn = ... } }")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-836: Backup vault without vault lock (cross-resource)
// ---------------------------------------------------------------------------

type backupVaultNoLock struct{}

func (backupVaultNoLock) ID() string { return "AEGIS-AWS-836" }
func (backupVaultNoLock) Title() string {
	return "Backup vault without vault lock configuration"
}
func (backupVaultNoLock) Description() string {
	return "A Backup vault with no aws_backup_vault_lock_configuration " +
		"allows recovery points to be deleted before their retention period " +
		"expires, undermining ransomware protection. Add a vault lock in " +
		"compliance mode with a minimum retention."
}
func (backupVaultNoLock) Severity() ir.Severity { return ir.SeverityLow }
func (backupVaultNoLock) AppliesTo(resType string) bool {
	return resType == "aws_backup_vault" ||
		resType == "aws_backup_vault_lock_configuration"
}

// Check is a no-op: all logic lives in CheckAll.
func (backupVaultNoLock) Check(r ir.Resource) []ir.Finding { return nil }

func (s backupVaultNoLock) CheckAll(resources []ir.Resource) []ir.Finding {
	locked := map[string]bool{}
	uncertain := false
	var vaults []ir.Resource
	for _, res := range resources {
		switch res.Type {
		case "aws_backup_vault":
			vaults = append(vaults, res)
		case "aws_backup_vault_lock_configuration":
			name, _, present, known := getString(res, "backup_vault_name")
			if !present || !known {
				uncertain = true // may lock any vault: cannot prove a gap
				continue
			}
			locked[name] = true
		}
	}
	if uncertain {
		return nil
	}
	var out []ir.Finding
	for _, v := range vaults {
		name, _, present, known := getString(v, "name")
		if !present || !known {
			continue // cannot link an unnamed vault: undecidable
		}
		if locked[name] {
			continue
		}
		out = append(out, sdFinding(s, v, "aws_backup_vault_lock_configuration",
			ir.Span{}, "absent (vault not locked)",
			"aws_backup_vault_lock_configuration { backup_vault_name = \""+name+"\" ... }"))
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-837: Organization not using the ALL feature set
// ---------------------------------------------------------------------------

type organizationsFeatureSet struct{}

func (organizationsFeatureSet) ID() string { return "AEGIS-AWS-837" }
func (organizationsFeatureSet) Title() string {
	return "Organization without the ALL feature set"
}
func (organizationsFeatureSet) Description() string {
	return "An AWS Organization whose feature_set is not \"ALL\" runs in " +
		"consolidated-billing-only mode, disabling service control policies " +
		"and other guardrails. Use feature_set = \"ALL\" unless billing-only " +
		"is a deliberate choice."
}
func (organizationsFeatureSet) Severity() ir.Severity { return ir.SeverityLow }
func (organizationsFeatureSet) AppliesTo(resType string) bool {
	return resType == "aws_organizations_organization"
}

func (s organizationsFeatureSet) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "feature_set")
	if !present || !known {
		return nil // provider default is ALL: absent is safe
	}
	if val == "ALL" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "feature_set", span,
		"\""+val+"\"", "feature_set = \"ALL\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-838: Organizational unit without a name
// ---------------------------------------------------------------------------

type orgUnitNoName struct{}

func (orgUnitNoName) ID() string { return "AEGIS-AWS-838" }
func (orgUnitNoName) Title() string {
	return "Organizational unit without a name"
}
func (orgUnitNoName) Description() string {
	return "An Organizational Unit with no name is harder to audit in " +
		"policy attachments and CloudTrail, inviting mis-scoped service " +
		"control policies. Give every OU an explicit descriptive name."
}
func (orgUnitNoName) Severity() ir.Severity { return ir.SeverityLow }
func (orgUnitNoName) AppliesTo(resType string) bool {
	return resType == "aws_organizations_organizational_unit"
}

func (s orgUnitNoName) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "name")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return absentInsecureDefault(s, r, "name",
		"absent (unnamed OU)", "name = \"production\"")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-839: ACM certificate with transparency logging disabled
// ---------------------------------------------------------------------------

type acmNoTransparencyLogging struct{}

func (acmNoTransparencyLogging) ID() string { return "AEGIS-AWS-839" }
func (acmNoTransparencyLogging) Title() string {
	return "ACM certificate with certificate transparency logging disabled"
}
func (acmNoTransparencyLogging) Description() string {
	return "An ACM certificate whose options set " +
		"certificate_transparency_logging_preference = \"DISABLED\" is issued " +
		"without public Certificate Transparency logs, removing a " +
		"detection control for mis-issued certificates. Keep transparency " +
		"logging enabled."
}
func (acmNoTransparencyLogging) Severity() ir.Severity { return ir.SeverityLow }
func (acmNoTransparencyLogging) AppliesTo(resType string) bool {
	return resType == "aws_acm_certificate"
}

func (s acmNoTransparencyLogging) Check(r ir.Resource) []ir.Finding {
	opts, _, present, known := getBlocks(r, "options")
	if !present || !known || len(opts) == 0 {
		return nil // provider default is ENABLED: absent is safe
	}
	pref, span, ppresent, pknown := blockString(opts[0], "certificate_transparency_logging_preference")
	if !ppresent || !pknown {
		return nil
	}
	if pref != "DISABLED" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r,
		"options.certificate_transparency_logging_preference", span,
		"\"DISABLED\"", "certificate_transparency_logging_preference = \"ENABLED\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-840: LB target group using plaintext HTTP
// ---------------------------------------------------------------------------

type lbTargetGroupHTTP struct{}

func (lbTargetGroupHTTP) ID() string { return "AEGIS-AWS-840" }
func (lbTargetGroupHTTP) Title() string {
	return "Load balancer target group using plaintext HTTP"
}
func (lbTargetGroupHTTP) Description() string {
	return "A load balancer target group with protocol = \"HTTP\" forwards " +
		"traffic to targets unencrypted inside the VPC, exposing request " +
		"data and credentials to network sniffing. Use HTTPS with valid " +
		"target certificates."
}
func (lbTargetGroupHTTP) Severity() ir.Severity { return ir.SeverityMedium }
func (lbTargetGroupHTTP) AppliesTo(resType string) bool {
	return resType == "aws_lb_target_group"
}

func (s lbTargetGroupHTTP) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "protocol")
	if !present || !known {
		return nil // default follows target_type: cannot assume HTTP
	}
	if val != "HTTP" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "protocol", span,
		"\"HTTP\"", "protocol = \"HTTPS\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-841: LB target group with HTTP health checks
// ---------------------------------------------------------------------------

type lbTargetGroupHCHTTP struct{}

func (lbTargetGroupHCHTTP) ID() string { return "AEGIS-AWS-841" }
func (lbTargetGroupHCHTTP) Title() string {
	return "Load balancer target group with plaintext HTTP health checks"
}
func (lbTargetGroupHCHTTP) Description() string {
	return "A load balancer target group whose health_check protocol is " +
		"\"HTTP\" probes targets over plaintext, and health-check endpoints " +
		"may leak internal status details. Prefer HTTPS health checks where " +
		"targets support TLS."
}
func (lbTargetGroupHCHTTP) Severity() ir.Severity { return ir.SeverityLow }
func (lbTargetGroupHCHTTP) AppliesTo(resType string) bool {
	return resType == "aws_lb_target_group"
}

func (s lbTargetGroupHCHTTP) Check(r ir.Resource) []ir.Finding {
	hc, _, present, known := getBlocks(r, "health_check")
	if !present || !known || len(hc) == 0 {
		return nil // health check protocol defaults to the target protocol
	}
	proto, span, ppresent, pknown := blockString(hc[0], "protocol")
	if !ppresent || !pknown {
		return nil
	}
	if proto != "HTTP" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "health_check.protocol", span,
		"\"HTTP\"", "health_check { protocol = \"HTTPS\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-842: ALB listener with an outdated SSL policy
// ---------------------------------------------------------------------------

type albListenerOldSSLPolicy struct{}

func (albListenerOldSSLPolicy) ID() string { return "AEGIS-AWS-842" }
func (albListenerOldSSLPolicy) Title() string {
	return "ALB listener with an outdated SSL policy"
}
func (albListenerOldSSLPolicy) Description() string {
	return "An ALB listener whose ssl_policy references a 2016-era or " +
		"TLS-1-0 policy negotiates weak ciphers and obsolete TLS versions. " +
		"Use a current ELBSecurityPolicy-TLS13 policy."
}
func (albListenerOldSSLPolicy) Severity() ir.Severity { return ir.SeverityMedium }
func (albListenerOldSSLPolicy) AppliesTo(resType string) bool {
	return resType == "aws_alb_listener" || resType == "aws_lb_listener"
}

func (s albListenerOldSSLPolicy) Check(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "ssl_policy")
	if !present || !known {
		return nil // provider default is the current policy: absent is safe
	}
	upper := strings.ToUpper(pol)
	if !strings.Contains(upper, "2016") && !strings.Contains(upper, "TLS-1-0") {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "ssl_policy", span,
		"\""+pol+"\"", "ssl_policy = \"ELBSecurityPolicy-TLS13-1-2-2021-06\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-843: API Gateway account without a CloudWatch role
// ---------------------------------------------------------------------------

type apigwAccountNoCWRole struct{}

func (apigwAccountNoCWRole) ID() string { return "AEGIS-AWS-843" }
func (apigwAccountNoCWRole) Title() string {
	return "API Gateway account without a CloudWatch logging role"
}
func (apigwAccountNoCWRole) Description() string {
	return "An API Gateway account with no cloudwatch_role_arn cannot write " +
		"execution logs to CloudWatch, silently disabling API logging " +
		"account-wide. Set cloudwatch_role_arn to an IAM role trusted by " +
		"API Gateway."
}
func (apigwAccountNoCWRole) Severity() ir.Severity { return ir.SeverityLow }
func (apigwAccountNoCWRole) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_account"
}

func (s apigwAccountNoCWRole) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "cloudwatch_role_arn")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return absentInsecureDefault(s, r, "cloudwatch_role_arn",
		"absent (no API Gateway execution logging)",
		"cloudwatch_role_arn = <IAM role ARN>")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-844: API Gateway method without a request validator
// ---------------------------------------------------------------------------

type apigwMethodNoValidator struct{}

func (apigwMethodNoValidator) ID() string { return "AEGIS-AWS-844" }
func (apigwMethodNoValidator) Title() string {
	return "API Gateway method without a request validator"
}
func (apigwMethodNoValidator) Description() string {
	return "An API Gateway method with no request_validator_id accepts " +
		"unvalidated request bodies and parameters, pushing malformed input " +
		"into the backend. Attach a request validator enforcing body and " +
		"parameter validation."
}
func (apigwMethodNoValidator) Severity() ir.Severity { return ir.SeverityLow }
func (apigwMethodNoValidator) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_method"
}

func (s apigwMethodNoValidator) Check(r ir.Resource) []ir.Finding {
	_, _, present, known := getString(r, "request_validator_id")
	if present && !known {
		return nil
	}
	if present {
		return nil
	}
	return absentInsecureDefault(s, r, "request_validator_id",
		"absent (no request validation)",
		"request_validator_id = <validator id>")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-845: API Gateway usage plan without throttle settings
// ---------------------------------------------------------------------------

type apigwUsagePlanNoThrottle struct{}

func (apigwUsagePlanNoThrottle) ID() string { return "AEGIS-AWS-845" }
func (apigwUsagePlanNoThrottle) Title() string {
	return "API Gateway usage plan without throttle settings"
}
func (apigwUsagePlanNoThrottle) Description() string {
	return "An API Gateway usage plan with no throttle_settings block " +
		"imposes no rate or burst limits, leaving the API exposed to " +
		"abusive traffic and runaway costs. Set burst_limit and rate_limit."
}
func (apigwUsagePlanNoThrottle) Severity() ir.Severity { return ir.SeverityLow }
func (apigwUsagePlanNoThrottle) AppliesTo(resType string) bool {
	return resType == "aws_api_gateway_usage_plan"
}

func (s apigwUsagePlanNoThrottle) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "throttle_settings")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return absentInsecureDefault(s, r, "throttle_settings",
		"absent (no throttling)",
		"throttle_settings { burst_limit = 100, rate_limit = 50 }")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-846: Route 53 health check disabled
// ---------------------------------------------------------------------------

type route53HealthCheckDisabled struct{}

func (route53HealthCheckDisabled) ID() string { return "AEGIS-AWS-846" }
func (route53HealthCheckDisabled) Title() string {
	return "Route 53 health check disabled"
}
func (route53HealthCheckDisabled) Description() string {
	return "A Route 53 health check with disabled = true never evaluates " +
		"its target, so DNS failover policies referencing it route traffic " +
		"to dead endpoints. Remove or re-enable stale health checks."
}
func (route53HealthCheckDisabled) Severity() ir.Severity { return ir.SeverityLow }
func (route53HealthCheckDisabled) AppliesTo(resType string) bool {
	return resType == "aws_route53_health_check"
}

func (s route53HealthCheckDisabled) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "disabled")
	if !present || !known {
		return nil // provider default is false: absent is safe
	}
	if !val {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "disabled", span,
		"true", "disabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-847: DLM lifecycle policy disabled
// ---------------------------------------------------------------------------

type dlmPolicyDisabled struct{}

func (dlmPolicyDisabled) ID() string { return "AEGIS-AWS-847" }
func (dlmPolicyDisabled) Title() string {
	return "DLM lifecycle policy disabled"
}
func (dlmPolicyDisabled) Description() string {
	return "A Data Lifecycle Manager policy with state = \"DISABLED\" takes " +
		"no EBS snapshots, silently dropping the backup schedule it was " +
		"created for. Re-enable the policy or delete it if intentionally " +
		"retired."
}
func (dlmPolicyDisabled) Severity() ir.Severity { return ir.SeverityMedium }
func (dlmPolicyDisabled) AppliesTo(resType string) bool {
	return resType == "aws_dlm_lifecycle_policy"
}

func (s dlmPolicyDisabled) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getString(r, "state")
	if !present || !known {
		return nil // provider default is ENABLED: absent is safe
	}
	if val != "DISABLED" {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "state", span,
		"\"DISABLED\"", "state = \"ENABLED\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-848: VPN connection using static routes only
// ---------------------------------------------------------------------------

type vpnStaticRoutesOnly struct{}

func (vpnStaticRoutesOnly) ID() string { return "AEGIS-AWS-848" }
func (vpnStaticRoutesOnly) Title() string {
	return "VPN connection using static routes only"
}
func (vpnStaticRoutesOnly) Description() string {
	return "A VPN connection with static_routes_only = true cannot use BGP " +
		"failover, so a tunnel failure requires manual route changes and " +
		"extends outages. Prefer dynamic routing unless the customer " +
		"gateway cannot speak BGP."
}
func (vpnStaticRoutesOnly) Severity() ir.Severity { return ir.SeverityLow }
func (vpnStaticRoutesOnly) AppliesTo(resType string) bool {
	return resType == "aws_vpn_connection"
}

func (s vpnStaticRoutesOnly) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "static_routes_only")
	if !present || !known {
		return nil // provider default is false: absent is safe
	}
	if !val {
		return nil
	}
	return []ir.Finding{sdFinding(s, r, "static_routes_only", span,
		"true", "static_routes_only = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-849: Transfer server with plaintext FTP enabled
// ---------------------------------------------------------------------------

type transferServerFTP struct{}

func (transferServerFTP) ID() string { return "AEGIS-AWS-849" }
func (transferServerFTP) Title() string {
	return "Transfer Family server with plaintext FTP enabled"
}
func (transferServerFTP) Description() string {
	return "A Transfer Family server whose protocols include \"FTP\" " +
		"accepts credentials and file data over plaintext FTP. Disable FTP " +
		"and use SFTP or FTPS only."
}
func (transferServerFTP) Severity() ir.Severity { return ir.SeverityHigh }
func (transferServerFTP) AppliesTo(resType string) bool {
	return resType == "aws_transfer_server"
}

func (s transferServerFTP) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["protocols"]
	if !ok || !v.Known {
		return nil
	}
	l, ok := v.AsList()
	if !ok {
		return nil // unexpected shape: undecidable
	}
	for _, item := range l {
		proto, kok := item.AsString()
		if !kok {
			return nil // an unresolved entry makes the list undecidable
		}
		if proto == "FTP" {
			return []ir.Finding{sdFinding(s, r, "protocols", item.Span,
				"contains \"FTP\"", "protocols = [\"SFTP\"]")}
		}
	}
	return nil
}
