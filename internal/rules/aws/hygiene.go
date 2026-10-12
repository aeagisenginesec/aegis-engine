package aws

// Hygiene rules (AEGIS-AWS-601–626): Low-severity operational best practices.
//
// AEGIS-AWS-606 (EC2 detailed monitoring) duplicates AEGIS-AWS-310 and
// AEGIS-AWS-619 (EKS control plane logging) duplicates AEGIS-AWS-306;
// both are omitted.
//
// These are Checkov-parity checks, NOT security vulnerabilities. Every
// description starts with "Hygiene:" so users understand they are
// operational hygiene, not security-critical findings. Enterprise compliance
// programs expect them; security triage can safely deprioritize them.
//
// AEGIS-AWS-627 (VPC flow logs) duplicates AEGIS-AWS-209 and
// AEGIS-AWS-628 (S3 access logging) duplicates AEGIS-AWS-445;
// both are omitted.

import (
	"strings"

	"aegis/internal/ir"
)

// hygieneFinding builds a Low-severity hygiene finding with the standard
// evidence shape.
func hygieneFinding(id, title, desc string, r ir.Resource, attr string, span ir.Span, actual, expected string) ir.Finding {
	return ir.Finding{
		RuleID:      id,
		Title:       title,
		Description: desc,
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}
}

// stringListHas reports whether a list-of-strings value contains target
// (case-insensitive). Returns known=false when undecidable — never flag.
func stringListHas(v ir.Value, target string) (bool, bool) {
	if !v.Known {
		return false, false
	}
	l, ok := v.AsList()
	if !ok {
		return false, false
	}
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			continue
		}
		if strings.EqualFold(s, target) {
			return true, true
		}
	}
	return false, true
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-601: S3 bucket without lifecycle configuration (CKV2_AWS_61)
// ---------------------------------------------------------------------------

type s3NoLifecycle struct{}

func (s3NoLifecycle) ID() string { return "AEGIS-AWS-601" }
func (s3NoLifecycle) Title() string {
	return "S3 bucket without lifecycle configuration"
}
func (s3NoLifecycle) Description() string {
	return "Hygiene: S3 buckets should define lifecycle rules to transition " +
		"or expire objects, controlling long-term storage costs. Add a " +
		"lifecycle_rule block or an aws_s3_bucket_lifecycle_configuration resource."
}
func (s3NoLifecycle) Severity() ir.Severity { return ir.SeverityLow }
func (s3NoLifecycle) AppliesTo(resType string) bool {
	return resType == "aws_s3_bucket" ||
		resType == "aws_s3_bucket_lifecycle_configuration"
}
func (s3NoLifecycle) Check(r ir.Resource) []ir.Finding {
	if r.Type == "aws_s3_bucket_lifecycle_configuration" {
		return nil // standalone resource: lifecycle is configured by definition
	}
	blks, span, present, known := getBlocks(r, "lifecycle_rule")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-601",
			(s3NoLifecycle{}).Title(), (s3NoLifecycle{}).Description(),
			r, "lifecycle_rule", span, "absent",
			"lifecycle_rule block or aws_s3_bucket_lifecycle_configuration")}
	}
	return nil
}

var _ ir.CrossResourceRule = s3NoLifecycle{}

// CheckAll suppresses the inline finding when a standalone
// aws_s3_bucket_lifecycle_configuration is linked to the bucket.
// Buckets that serve as log-delivery targets are skipped: they are logging
// infrastructure, not data buckets.
func (s3NoLifecycle) CheckAll(resources []ir.Resource) []ir.Finding {
	configured := map[string]bool{}
	for _, r := range resources {
		if r.Type != "aws_s3_bucket_lifecycle_configuration" {
			continue
		}
		if addr, ok := linkedBucketAddr(r, resources); ok {
			configured[addr] = true
		}
	}
	logTargets := logDeliveryBuckets(resources)
	var out []ir.Finding
	for _, r := range resources {
		if r.Type != "aws_s3_bucket" {
			continue
		}
		for _, f := range (s3NoLifecycle{}).Check(r) {
			if !configured[r.Address()] && !logTargets[r.Address()] {
				out = append(out, f)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-604: Security group/rule without description (CKV_AWS_23)
// ---------------------------------------------------------------------------

type sgNoDescription struct{}

func (sgNoDescription) ID() string { return "AEGIS-AWS-604" }
func (sgNoDescription) Title() string {
	return "Security group or rule without description"
}
func (sgNoDescription) Description() string {
	return "Hygiene: Security groups and their rules should carry " +
		"descriptions so reviewers understand their purpose. Add a " +
		"description attribute."
}
func (sgNoDescription) Severity() ir.Severity { return ir.SeverityLow }
func (sgNoDescription) AppliesTo(resType string) bool {
	return resType == "aws_security_group" ||
		resType == "aws_security_group_rule" ||
		resType == "aws_default_security_group"
}
func (sgNoDescription) Check(r ir.Resource) []ir.Finding {
	// Check the resource-level description.
	desc, span, present, known := getString(r, "description")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	var out []ir.Finding
	if !present || desc == "" {
		out = append(out, hygieneFinding("AEGIS-AWS-604",
			(sgNoDescription{}).Title(), (sgNoDescription{}).Description(),
			r, "description", span, "absent or empty",
			"description attribute documenting the group or rule"))
	}
	// Check inline ingress/egress rule descriptions.
	for _, blkName := range []string{"ingress", "egress"} {
		blks, _, bpresent, bknown := getBlocks(r, blkName)
		if !bpresent || !bknown {
			continue
		}
		for i, blk := range blks {
			dv, ok := blk["description"]
			if !ok {
				out = append(out, hygieneFinding("AEGIS-AWS-604",
					(sgNoDescription{}).Title(), (sgNoDescription{}).Description(),
					r, blkName+"["+string(rune('0'+i))+"]"+".description",
					r.Span, "absent",
					"description on each inline "+blkName+" rule"))
				continue
			}
			if s, ok := dv.AsString(); ok && s == "" {
				out = append(out, hygieneFinding("AEGIS-AWS-604",
					(sgNoDescription{}).Title(), (sgNoDescription{}).Description(),
					r, blkName+".description", dv.Span, "empty",
					"non-empty description on each inline "+blkName+" rule"))
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-605: RDS instance without enhanced monitoring (CKV_AWS_118)
// ---------------------------------------------------------------------------

type rdsNoEnhancedMonitoring struct{}

func (rdsNoEnhancedMonitoring) ID() string { return "AEGIS-AWS-605" }
func (rdsNoEnhancedMonitoring) Title() string {
	return "RDS instance without enhanced monitoring"
}
func (rdsNoEnhancedMonitoring) Description() string {
	return "Hygiene: RDS instances should enable enhanced monitoring " +
		"(monitoring_interval > 0) for OS-level metrics that aid " +
		"troubleshooting. Set monitoring_interval to 1, 5, 10, 15, 30 or 60."
}
func (rdsNoEnhancedMonitoring) Severity() ir.Severity { return ir.SeverityLow }
func (rdsNoEnhancedMonitoring) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}
func (rdsNoEnhancedMonitoring) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attr("monitoring_interval")
	if !ok {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-605",
			(rdsNoEnhancedMonitoring{}).Title(), (rdsNoEnhancedMonitoring{}).Description(),
			r, "monitoring_interval", r.Span, "absent",
			"monitoring_interval set to 1, 5, 10, 15, 30 or 60")}
	}
	if !v.Known {
		return nil
	}
	n, ok := v.Raw.(float64)
	if !ok {
		return nil
	}
	if n == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-605",
			(rdsNoEnhancedMonitoring{}).Title(), (rdsNoEnhancedMonitoring{}).Description(),
			r, "monitoring_interval", v.Span, "0",
			"monitoring_interval set to 1, 5, 10, 15, 30 or 60")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-607: RDS Postgres without query logging (CKV2_AWS_30)
// ---------------------------------------------------------------------------

type rdsNoQueryLogging struct{}

func (rdsNoQueryLogging) ID() string { return "AEGIS-AWS-607" }
func (rdsNoQueryLogging) Title() string {
	return "RDS Postgres instance without query logging"
}
func (rdsNoQueryLogging) Description() string {
	return "Hygiene: RDS Postgres instances should export postgresql " +
		"logs to CloudWatch for query auditing. Add \"postgresql\" to " +
		"enabled_cloudwatch_logs_log_exports."
}
func (rdsNoQueryLogging) Severity() ir.Severity { return ir.SeverityLow }
func (rdsNoQueryLogging) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}
func (rdsNoQueryLogging) Check(r ir.Resource) []ir.Finding {
	engine, _, epresent, eknown := getString(r, "engine")
	if !epresent || !eknown {
		return nil // cannot tell if postgres: never flag
	}
	if !strings.HasPrefix(strings.ToLower(engine), "postgres") {
		return nil
	}
	v, ok := r.Attr("enabled_cloudwatch_logs_log_exports")
	if !ok {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-607",
			(rdsNoQueryLogging{}).Title(), (rdsNoQueryLogging{}).Description(),
			r, "enabled_cloudwatch_logs_log_exports", r.Span, "absent",
			"enabled_cloudwatch_logs_log_exports including \"postgresql\"")}
	}
	has, known := stringListHas(v, "postgresql")
	if !known {
		return nil
	}
	if !has {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-607",
			(rdsNoQueryLogging{}).Title(), (rdsNoQueryLogging{}).Description(),
			r, "enabled_cloudwatch_logs_log_exports", v.Span,
			"postgresql log export missing",
			"enabled_cloudwatch_logs_log_exports including \"postgresql\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-608: RDS instance without Performance Insights (CKV_AWS_353)
// ---------------------------------------------------------------------------

type rdsNoPerfInsights struct{}

func (rdsNoPerfInsights) ID() string { return "AEGIS-AWS-608" }
func (rdsNoPerfInsights) Title() string {
	return "RDS instance without Performance Insights"
}
func (rdsNoPerfInsights) Description() string {
	return "Hygiene: RDS instances should enable Performance Insights " +
		"for query-level performance analysis. Set " +
		"performance_insights_enabled = true."
}
func (rdsNoPerfInsights) Severity() ir.Severity { return ir.SeverityLow }
func (rdsNoPerfInsights) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}
func (rdsNoPerfInsights) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "performance_insights_enabled")
	if present && !known {
		return nil
	}
	if !present || !val {
		actual := "absent"
		if present {
			actual = "false"
		}
		return []ir.Finding{hygieneFinding("AEGIS-AWS-608",
			(rdsNoPerfInsights{}).Title(), (rdsNoPerfInsights{}).Description(),
			r, "performance_insights_enabled", span, actual,
			"performance_insights_enabled = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-609: Load balancer without access logging (CKV_AWS_91)
// ---------------------------------------------------------------------------

type lbNoAccessLogging struct{}

func (lbNoAccessLogging) ID() string { return "AEGIS-AWS-609" }
func (lbNoAccessLogging) Title() string {
	return "Load balancer without access logging"
}
func (lbNoAccessLogging) Description() string {
	return "Hygiene: Load balancers should log access to S3 for traffic " +
		"analysis and incident investigation. Add an access_logs block " +
		"with a bucket."
}
func (lbNoAccessLogging) Severity() ir.Severity { return ir.SeverityLow }
func (lbNoAccessLogging) AppliesTo(resType string) bool {
	return resType == "aws_lb" || resType == "aws_alb" || resType == "aws_elb"
}
func (lbNoAccessLogging) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "access_logs")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-609",
			(lbNoAccessLogging{}).Title(), (lbNoAccessLogging{}).Description(),
			r, "access_logs", span, "absent",
			"access_logs block with bucket configured")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-610: CloudWatch log group without retention (CKV_AWS_66)
// ---------------------------------------------------------------------------

type logGroupNoRetention struct{}

func (logGroupNoRetention) ID() string { return "AEGIS-AWS-610" }
func (logGroupNoRetention) Title() string {
	return "CloudWatch log group without retention period"
}
func (logGroupNoRetention) Description() string {
	return "Hygiene: CloudWatch log groups should set retention_in_days " +
		"so logs expire on a schedule instead of accumulating forever. " +
		"Set retention_in_days explicitly."
}
func (logGroupNoRetention) Severity() ir.Severity { return ir.SeverityLow }
func (logGroupNoRetention) AppliesTo(resType string) bool {
	return resType == "aws_cloudwatch_log_group"
}
func (logGroupNoRetention) Check(r ir.Resource) []ir.Finding {
	_, span, present, known := getString(r, "retention_in_days")
	if present && !known {
		return nil
	}
	// Also accept numeric form.
	if !present {
		if v, ok := r.Attr("retention_in_days"); ok && v.Known {
			if _, isNum := v.Raw.(float64); isNum {
				return nil
			}
		}
		return []ir.Finding{hygieneFinding("AEGIS-AWS-610",
			(logGroupNoRetention{}).Title(), (logGroupNoRetention{}).Description(),
			r, "retention_in_days", span, "absent",
			"retention_in_days set to an explicit value")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-611: Neptune cluster without logging (CKV_AWS_101)
// ---------------------------------------------------------------------------

type neptuneNoLogging struct{}

func (neptuneNoLogging) ID() string { return "AEGIS-AWS-611" }
func (neptuneNoLogging) Title() string {
	return "Neptune cluster without CloudWatch log exports"
}
func (neptuneNoLogging) Description() string {
	return "Hygiene: Neptune clusters should export audit logs to " +
		"CloudWatch. Set enable_cloudwatch_logs_exports (e.g. [\"audit\"])."
}
func (neptuneNoLogging) Severity() ir.Severity { return ir.SeverityLow }
func (neptuneNoLogging) AppliesTo(resType string) bool {
	return resType == "aws_neptune_cluster"
}
func (neptuneNoLogging) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attr("enable_cloudwatch_logs_exports")
	if !ok {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-611",
			(neptuneNoLogging{}).Title(), (neptuneNoLogging{}).Description(),
			r, "enable_cloudwatch_logs_exports", r.Span, "absent",
			"enable_cloudwatch_logs_exports with audit log type")}
	}
	if !v.Known {
		return nil
	}
	if l, ok := v.AsList(); ok && len(l) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-611",
			(neptuneNoLogging{}).Title(), (neptuneNoLogging{}).Description(),
			r, "enable_cloudwatch_logs_exports", v.Span, "empty list",
			"enable_cloudwatch_logs_exports with audit log type")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-612: Neptune without adequate backup retention (CKV_AWS_361)
// ---------------------------------------------------------------------------

type neptuneShortBackup struct{}

func (neptuneShortBackup) ID() string { return "AEGIS-AWS-612" }
func (neptuneShortBackup) Title() string {
	return "Neptune cluster without adequate backup retention"
}
func (neptuneShortBackup) Description() string {
	return "Hygiene: Neptune clusters should retain automated backups " +
		"for at least 7 days. Set backup_retention_period >= 7."
}
func (neptuneShortBackup) Severity() ir.Severity { return ir.SeverityLow }
func (neptuneShortBackup) AppliesTo(resType string) bool {
	return resType == "aws_neptune_cluster"
}
func (neptuneShortBackup) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attr("backup_retention_period")
	if !ok {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-612",
			(neptuneShortBackup{}).Title(), (neptuneShortBackup{}).Description(),
			r, "backup_retention_period", r.Span, "absent",
			"backup_retention_period >= 7")}
	}
	if !v.Known {
		return nil
	}
	n, ok := v.Raw.(float64)
	if !ok {
		return nil
	}
	if n < 7 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-612",
			(neptuneShortBackup{}).Title(), (neptuneShortBackup{}).Description(),
			r, "backup_retention_period", v.Span, "less than 7 days",
			"backup_retention_period >= 7")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-613: WAFv2 web ACL without logging (CKV2_AWS_31)
// ---------------------------------------------------------------------------

type wafv2NoLogging struct{}

func (wafv2NoLogging) ID() string { return "AEGIS-AWS-613" }
func (wafv2NoLogging) Title() string {
	return "WAFv2 web ACL without logging configuration"
}
func (wafv2NoLogging) Description() string {
	return "Hygiene: WAFv2 web ACLs should log to CloudWatch/S3/Kinesis " +
		"for request analysis. Add an " +
		"aws_wafv2_web_acl_logging_configuration resource."
}
func (wafv2NoLogging) Severity() ir.Severity { return ir.SeverityLow }
func (wafv2NoLogging) AppliesTo(resType string) bool {
	return resType == "aws_wafv2_web_acl" ||
		resType == "aws_wafv2_web_acl_logging_configuration"
}
func (wafv2NoLogging) Check(ir.Resource) []ir.Finding { return nil }

var _ ir.CrossResourceRule = wafv2NoLogging{}

func (wafv2NoLogging) CheckAll(resources []ir.Resource) []ir.Finding {
	logged := map[string]bool{}
	for _, r := range resources {
		if r.Type != "aws_wafv2_web_acl_logging_configuration" {
			continue
		}
		v, ok := r.Attr("resource_arn")
		if !ok || !v.IsRef() {
			continue
		}
		parts := strings.Split(v.Ref, ".")
		if len(parts) >= 2 {
			logged[parts[0]+"."+parts[1]] = true
		}
	}
	// A logging configuration whose resource_arn is unresolvable might log
	// any web ACL.
	uncertain := companionLinkUncertain(resources, "aws_wafv2_web_acl_logging_configuration", "resource_arn")
	var out []ir.Finding
	for _, r := range resources {
		if r.Type != "aws_wafv2_web_acl" {
			continue
		}
		if !logged[r.Address()] && !uncertain {
			out = append(out, hygieneFinding("AEGIS-AWS-613",
				(wafv2NoLogging{}).Title(), (wafv2NoLogging{}).Description(),
				r, "logging_configuration", r.Span, "absent",
				"aws_wafv2_web_acl_logging_configuration linked to the ACL"))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-614: AppSync API without logging (CKV_AWS_193)
// ---------------------------------------------------------------------------

type appsyncNoLogging struct{}

func (appsyncNoLogging) ID() string { return "AEGIS-AWS-614" }
func (appsyncNoLogging) Title() string {
	return "AppSync GraphQL API without logging"
}
func (appsyncNoLogging) Description() string {
	return "Hygiene: AppSync APIs should enable field-level logging to " +
		"CloudWatch. Add a log_config block."
}
func (appsyncNoLogging) Severity() ir.Severity { return ir.SeverityLow }
func (appsyncNoLogging) AppliesTo(resType string) bool {
	return resType == "aws_appsync_graphql_api"
}
func (appsyncNoLogging) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "log_config")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-614",
			(appsyncNoLogging{}).Title(), (appsyncNoLogging{}).Description(),
			r, "log_config", span, "absent", "log_config block enabled")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-615: MQ broker without audit logging (CKV_AWS_197)
// ---------------------------------------------------------------------------

type mqNoAuditLogging struct{}

func (mqNoAuditLogging) ID() string { return "AEGIS-AWS-615" }
func (mqNoAuditLogging) Title() string {
	return "MQ broker without audit logging"
}
func (mqNoAuditLogging) Description() string {
	return "Hygiene: MQ brokers should enable audit logging for " +
		"administrative actions. Set logs { audit = true }."
}
func (mqNoAuditLogging) Severity() ir.Severity { return ir.SeverityLow }
func (mqNoAuditLogging) AppliesTo(resType string) bool {
	return resType == "aws_mq_broker" || resType == "aws_mq_configuration"
}
func (mqNoAuditLogging) Check(r ir.Resource) []ir.Finding {
	if r.Type == "aws_mq_configuration" {
		return nil
	}
	blks, span, present, known := getBlocks(r, "logs")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-615",
			(mqNoAuditLogging{}).Title(), (mqNoAuditLogging{}).Description(),
			r, "logs.audit", span, "absent", "logs block with audit = true")}
	}
	audit, _, _, aknown := blockBool(blks[0], "audit")
	if !aknown {
		return nil
	}
	if !audit {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-615",
			(mqNoAuditLogging{}).Title(), (mqNoAuditLogging{}).Description(),
			r, "logs.audit", span, "false", "logs block with audit = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-617: CodeBuild project without logging (CKV_AWS_314)
// ---------------------------------------------------------------------------

type codebuildNoLogging struct{}

func (codebuildNoLogging) ID() string { return "AEGIS-AWS-617" }
func (codebuildNoLogging) Title() string {
	return "CodeBuild project without logging configuration"
}
func (codebuildNoLogging) Description() string {
	return "Hygiene: CodeBuild projects should log builds to CloudWatch " +
		"and/or S3. Add a logs_config block."
}
func (codebuildNoLogging) Severity() ir.Severity { return ir.SeverityLow }
func (codebuildNoLogging) AppliesTo(resType string) bool {
	return resType == "aws_codebuild_project"
}
func (codebuildNoLogging) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "logs_config")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-617",
			(codebuildNoLogging{}).Title(), (codebuildNoLogging{}).Description(),
			r, "logs_config", span, "absent",
			"logs_config block with cloudwatch_logs and/or s3_logs")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-618: Elasticsearch without audit logging (CKV_AWS_317)
// ---------------------------------------------------------------------------

type esNoAuditLogging struct{}

func (esNoAuditLogging) ID() string { return "AEGIS-AWS-618" }
func (esNoAuditLogging) Title() string {
	return "Elasticsearch domain without audit logging"
}
func (esNoAuditLogging) Description() string {
	return "Hygiene: Elasticsearch/OpenSearch domains should publish " +
		"audit logs. Add a log_publishing_options block with " +
		"log_type AUDIT_LOGS."
}
func (esNoAuditLogging) Severity() ir.Severity { return ir.SeverityLow }
func (esNoAuditLogging) AppliesTo(resType string) bool {
	return resType == "aws_elasticsearch_domain" ||
		resType == "aws_opensearch_domain"
}
func (esNoAuditLogging) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "log_publishing_options")
	if present && !known {
		return nil
	}
	for _, blk := range blks {
		lt, _, _, lknown := blockString(blk, "log_type")
		if !lknown {
			continue
		}
		if strings.Contains(strings.ToUpper(lt), "AUDIT") {
			return nil // audit logging present
		}
	}
	return []ir.Finding{hygieneFinding("AEGIS-AWS-618",
		(esNoAuditLogging{}).Title(), (esNoAuditLogging{}).Description(),
		r, "log_publishing_options", span, "no AUDIT_LOGS option",
		"log_publishing_options with log_type AUDIT_LOGS")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-620: MQ broker without general logging (CKV_AWS_48)
// ---------------------------------------------------------------------------

type mqNoGeneralLogging struct{}

func (mqNoGeneralLogging) ID() string { return "AEGIS-AWS-620" }
func (mqNoGeneralLogging) Title() string {
	return "MQ broker without general logging"
}
func (mqNoGeneralLogging) Description() string {
	return "Hygiene: MQ brokers should enable general logging for " +
		"operational visibility. Set logs { general = true }."
}
func (mqNoGeneralLogging) Severity() ir.Severity { return ir.SeverityLow }
func (mqNoGeneralLogging) AppliesTo(resType string) bool {
	return resType == "aws_mq_broker"
}
func (mqNoGeneralLogging) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "logs")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-620",
			(mqNoGeneralLogging{}).Title(), (mqNoGeneralLogging{}).Description(),
			r, "logs.general", span, "absent", "logs block with general = true")}
	}
	general, _, _, gknown := blockBool(blks[0], "general")
	if !gknown {
		return nil
	}
	if !general {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-620",
			(mqNoGeneralLogging{}).Title(), (mqNoGeneralLogging{}).Description(),
			r, "logs.general", span, "false", "logs block with general = true")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-622: MSK cluster without logging (CKV_AWS_80)
// ---------------------------------------------------------------------------

type mskNoLogging struct{}

func (mskNoLogging) ID() string { return "AEGIS-AWS-622" }
func (mskNoLogging) Title() string {
	return "MSK cluster without logging"
}
func (mskNoLogging) Description() string {
	return "Hygiene: MSK clusters should enable broker logging to " +
		"CloudWatch, S3 or Firehose. Add a logging_info block."
}
func (mskNoLogging) Severity() ir.Severity { return ir.SeverityLow }
func (mskNoLogging) AppliesTo(resType string) bool {
	return resType == "aws_msk_cluster"
}
func (mskNoLogging) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "logging_info")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-622",
			(mskNoLogging{}).Title(), (mskNoLogging{}).Description(),
			r, "logging_info", span, "absent",
			"logging_info block with broker_logs configured")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-623: Elasticsearch without domain logging (CKV_AWS_84)
// ---------------------------------------------------------------------------

type esNoDomainLogging struct{}

func (esNoDomainLogging) ID() string { return "AEGIS-AWS-623" }
func (esNoDomainLogging) Title() string {
	return "Elasticsearch domain without any log publishing"
}
func (esNoDomainLogging) Description() string {
	return "Hygiene: Elasticsearch/OpenSearch domains should publish " +
		"at least one log type (search, index, error or audit). Add a " +
		"log_publishing_options block. (Audit-specific coverage: AEGIS-AWS-618.)"
}
func (esNoDomainLogging) Severity() ir.Severity { return ir.SeverityLow }
func (esNoDomainLogging) AppliesTo(resType string) bool {
	return resType == "aws_elasticsearch_domain" ||
		resType == "aws_opensearch_domain"
}
func (esNoDomainLogging) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "log_publishing_options")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-623",
			(esNoDomainLogging{}).Title(), (esNoDomainLogging{}).Description(),
			r, "log_publishing_options", span, "absent",
			"log_publishing_options block with at least one log type")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-624: DocumentDB cluster without logging (CKV_AWS_85)
// ---------------------------------------------------------------------------

type docdbNoLogging struct{}

func (docdbNoLogging) ID() string { return "AEGIS-AWS-624" }
func (docdbNoLogging) Title() string {
	return "DocumentDB cluster without CloudWatch log exports"
}
func (docdbNoLogging) Description() string {
	return "Hygiene: DocumentDB clusters should export profiler and " +
		"audit logs to CloudWatch. Set enabled_cloudwatch_logs_exports."
}
func (docdbNoLogging) Severity() ir.Severity { return ir.SeverityLow }
func (docdbNoLogging) AppliesTo(resType string) bool {
	return resType == "aws_docdb_cluster"
}
func (docdbNoLogging) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attr("enabled_cloudwatch_logs_exports")
	if !ok {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-624",
			(docdbNoLogging{}).Title(), (docdbNoLogging{}).Description(),
			r, "enabled_cloudwatch_logs_exports", r.Span, "absent",
			"enabled_cloudwatch_logs_exports with profiler/audit")}
	}
	if !v.Known {
		return nil
	}
	if l, ok := v.AsList(); ok && len(l) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-624",
			(docdbNoLogging{}).Title(), (docdbNoLogging{}).Description(),
			r, "enabled_cloudwatch_logs_exports", v.Span, "empty list",
			"enabled_cloudwatch_logs_exports with profiler/audit")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-625: CloudFront distribution without access logging (CKV_AWS_86)
// ---------------------------------------------------------------------------

type cloudfrontNoLogging struct{}

func (cloudfrontNoLogging) ID() string { return "AEGIS-AWS-625" }
func (cloudfrontNoLogging) Title() string {
	return "CloudFront distribution without access logging"
}
func (cloudfrontNoLogging) Description() string {
	return "Hygiene: CloudFront distributions should log access to S3 " +
		"for traffic analysis. Add a logging_config block with a bucket."
}
func (cloudfrontNoLogging) Severity() ir.Severity { return ir.SeverityLow }
func (cloudfrontNoLogging) AppliesTo(resType string) bool {
	return resType == "aws_cloudfront_distribution"
}
func (cloudfrontNoLogging) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "logging_config")
	if present && !known {
		return nil
	}
	if !present || len(blks) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-625",
			(cloudfrontNoLogging{}).Title(), (cloudfrontNoLogging{}).Description(),
			r, "logging_config", span, "absent",
			"logging_config block with S3 bucket")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-626: DocumentDB without adequate backup retention (CKV_AWS_360)
// ---------------------------------------------------------------------------

type docdbShortBackup struct{}

func (docdbShortBackup) ID() string { return "AEGIS-AWS-626" }
func (docdbShortBackup) Title() string {
	return "DocumentDB cluster without adequate backup retention"
}
func (docdbShortBackup) Description() string {
	return "Hygiene: DocumentDB clusters should retain automated backups " +
		"for at least 7 days. Set backup_retention_period >= 7."
}
func (docdbShortBackup) Severity() ir.Severity { return ir.SeverityLow }
func (docdbShortBackup) AppliesTo(resType string) bool {
	return resType == "aws_docdb_cluster"
}
func (docdbShortBackup) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attr("backup_retention_period")
	if !ok {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-626",
			(docdbShortBackup{}).Title(), (docdbShortBackup{}).Description(),
			r, "backup_retention_period", r.Span, "absent",
			"backup_retention_period >= 7")}
	}
	if !v.Known {
		return nil
	}
	n, ok := v.Raw.(float64)
	if !ok {
		return nil
	}
	if n < 7 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-626",
			(docdbShortBackup{}).Title(), (docdbShortBackup{}).Description(),
			r, "backup_retention_period", v.Span, "less than 7 days",
			"backup_retention_period >= 7")}
	}
	return nil
}

// HygieneRules returns the hygiene pack in ID order (601, 604–605, 607–618,
// 620–626). Omitted as duplicates of existing rules: 606→310, 619→306,
// 627→209, 628→445. Removed as scanner noise (flagged every bucket,
// including fully-hardened ones): 602 (event notifications), 603
// (cross-region replication).
func HygieneRules() []ir.Rule {
	return []ir.Rule{
		s3NoLifecycle{},           // AEGIS-AWS-601
		sgNoDescription{},         // AEGIS-AWS-604
		rdsNoEnhancedMonitoring{}, // AEGIS-AWS-605
		rdsNoQueryLogging{},       // AEGIS-AWS-607
		rdsNoPerfInsights{},       // AEGIS-AWS-608
		lbNoAccessLogging{},       // AEGIS-AWS-609
		logGroupNoRetention{},     // AEGIS-AWS-610
		neptuneNoLogging{},        // AEGIS-AWS-611
		neptuneShortBackup{},      // AEGIS-AWS-612
		wafv2NoLogging{},          // AEGIS-AWS-613
		appsyncNoLogging{},        // AEGIS-AWS-614
		mqNoAuditLogging{},        // AEGIS-AWS-615
		codebuildNoLogging{},      // AEGIS-AWS-617
		esNoAuditLogging{},        // AEGIS-AWS-618
		mqNoGeneralLogging{},      // AEGIS-AWS-620
		mskNoLogging{},            // AEGIS-AWS-622
		esNoDomainLogging{},       // AEGIS-AWS-623
		docdbNoLogging{},          // AEGIS-AWS-624
		cloudfrontNoLogging{},     // AEGIS-AWS-625
		docdbShortBackup{},        // AEGIS-AWS-626
	}
}
