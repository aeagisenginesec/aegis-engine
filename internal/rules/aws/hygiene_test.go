package aws

import (
	"testing"

	"aegis/internal/ir"
)

// Minimal per-rule tests for the hygiene pack (AEGIS-AWS-601–626):
// vulnerable fires, compliant stays silent, unknown stays silent.

func TestHygieneRulesInIDOrder(t *testing.T) {
	rules := HygieneRules()
	want := []string{
		"AEGIS-AWS-601", "AEGIS-AWS-602", "AEGIS-AWS-603",
		"AEGIS-AWS-604", "AEGIS-AWS-605",
		"AEGIS-AWS-607", "AEGIS-AWS-608", "AEGIS-AWS-609",
		"AEGIS-AWS-610", "AEGIS-AWS-611", "AEGIS-AWS-612",
		"AEGIS-AWS-613", "AEGIS-AWS-614", "AEGIS-AWS-615",
		"AEGIS-AWS-617", "AEGIS-AWS-618",
		"AEGIS-AWS-620", "AEGIS-AWS-621", "AEGIS-AWS-622",
		"AEGIS-AWS-623", "AEGIS-AWS-624", "AEGIS-AWS-625",
		"AEGIS-AWS-626",
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d hygiene rules, got %d", len(want), len(rules))
	}
	for i, r := range rules {
		if r.ID() != want[i] {
			t.Errorf("rule %d: want %s, got %s", i, want[i], r.ID())
		}
		if r.Severity() != ir.SeverityLow {
			t.Errorf("%s: severity must be low, got %s", r.ID(), r.Severity())
		}
	}
}

// checkAll runs a CrossResourceRule's CheckAll.
func checkAll(rule ir.CrossResourceRule, resources ...ir.Resource) []ir.Finding {
	return rule.CheckAll(resources)
}

func Test601_S3NoLifecycle(t *testing.T) {
	rule := s3NoLifecycle{}
	vuln := res("aws_s3_bucket", "b", map[string]ir.Value{})
	if got := checkAll(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_s3_bucket", "b", map[string]ir.Value{
		"lifecycle_rule": blks(2, blk("id", ks("r1", 2))),
	})
	if got := checkAll(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
	// Standalone lifecycle configuration suppresses.
	standalone := res("aws_s3_bucket_lifecycle_configuration", "c", map[string]ir.Value{
		"bucket": ks("b", 2),
	})
	if got := checkAll(rule, vuln, standalone); len(got) != 0 {
		t.Errorf("standalone: want 0 findings, got %d", len(got))
	}
	// Unknown block shape: silent.
	unk := res("aws_s3_bucket", "b", map[string]ir.Value{
		"lifecycle_rule": ku(2),
	})
	if got := checkAll(rule, unk); len(got) != 0 {
		t.Errorf("unknown: want 0 findings, got %d", len(got))
	}
}

func Test602_S3NoNotifications(t *testing.T) {
	rule := s3NoNotifications{}
	vuln := res("aws_s3_bucket", "b", map[string]ir.Value{})
	if got := checkAll(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	notif := res("aws_s3_bucket_notification", "n", map[string]ir.Value{
		"bucket": ks("b", 2),
	})
	if got := checkAll(rule, vuln, notif); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test603_S3NoReplication(t *testing.T) {
	rule := s3NoReplication{}
	vuln := res("aws_s3_bucket", "b", map[string]ir.Value{})
	if got := checkAll(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_s3_bucket", "b", map[string]ir.Value{
		"replication_configuration": blks(2, blk("role", ks("r", 2))),
	})
	if got := checkAll(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test604_SGNoDescription(t *testing.T) {
	rule := sgNoDescription{}
	vuln := res("aws_security_group", "sg", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_security_group", "sg", map[string]ir.Value{
		"description": ks("web sg", 2),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
	// Inline rule without description fires too.
	inline := res("aws_security_group", "sg", map[string]ir.Value{
		"description": ks("web sg", 2),
		"ingress":     blks(3, blk("from_port", kv(true, 3))),
	})
	if got := runRule(rule, inline); len(got) != 1 {
		t.Errorf("inline rule: want 1 finding, got %d", len(got))
	}
}

func Test605_RDSNoEnhancedMonitoring(t *testing.T) {
	rule := rdsNoEnhancedMonitoring{}
	vuln := res("aws_db_instance", "db", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	zero := res("aws_db_instance", "db", map[string]ir.Value{
		"monitoring_interval": {Raw: float64(0), Known: true, Span: spanAt(2)},
	})
	if got := runRule(rule, zero); len(got) != 1 {
		t.Errorf("zero: want 1 finding, got %d", len(got))
	}
	ok := res("aws_db_instance", "db", map[string]ir.Value{
		"monitoring_interval": {Raw: float64(60), Known: true, Span: spanAt(2)},
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test607_RDSNoQueryLogging(t *testing.T) {
	rule := rdsNoQueryLogging{}
	vuln := res("aws_db_instance", "db", map[string]ir.Value{
		"engine": ks("postgres", 2),
	})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_db_instance", "db", map[string]ir.Value{
		"engine":                              ks("postgres", 2),
		"enabled_cloudwatch_logs_log_exports": strList(3, "postgresql"),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
	// Non-postgres: silent.
	mysql := res("aws_db_instance", "db", map[string]ir.Value{
		"engine": ks("mysql", 2),
	})
	if got := runRule(rule, mysql); len(got) != 0 {
		t.Errorf("mysql: want 0 findings, got %d", len(got))
	}
}

func Test608_RDSNoPerfInsights(t *testing.T) {
	rule := rdsNoPerfInsights{}
	vuln := res("aws_db_instance", "db", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_db_instance", "db", map[string]ir.Value{
		"performance_insights_enabled": kv(true, 2),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test609_LBNoAccessLogging(t *testing.T) {
	rule := lbNoAccessLogging{}
	vuln := res("aws_lb", "lb", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_lb", "lb", map[string]ir.Value{
		"access_logs": blks(2, blk("bucket", ks("logs", 2))),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test610_LogGroupNoRetention(t *testing.T) {
	rule := logGroupNoRetention{}
	vuln := res("aws_cloudwatch_log_group", "lg", map[string]ir.Value{
		"name": ks("app", 2),
	})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_cloudwatch_log_group", "lg", map[string]ir.Value{
		"name":              ks("app", 2),
		"retention_in_days": {Raw: float64(30), Known: true, Span: spanAt(3)},
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test611_NeptuneNoLogging(t *testing.T) {
	rule := neptuneNoLogging{}
	vuln := res("aws_neptune_cluster", "n", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_neptune_cluster", "n", map[string]ir.Value{
		"enable_cloudwatch_logs_exports": strList(2, "audit"),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test612_NeptuneShortBackup(t *testing.T) {
	rule := neptuneShortBackup{}
	vuln := res("aws_neptune_cluster", "n", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	short := res("aws_neptune_cluster", "n", map[string]ir.Value{
		"backup_retention_period": {Raw: float64(1), Known: true, Span: spanAt(2)},
	})
	if got := runRule(rule, short); len(got) != 1 {
		t.Errorf("short: want 1 finding, got %d", len(got))
	}
	ok := res("aws_neptune_cluster", "n", map[string]ir.Value{
		"backup_retention_period": {Raw: float64(7), Known: true, Span: spanAt(2)},
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test613_WAFv2NoLogging(t *testing.T) {
	rule := wafv2NoLogging{}
	vuln := res("aws_wafv2_web_acl", "acl", map[string]ir.Value{})
	if got := checkAll(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	logging := res("aws_wafv2_web_acl_logging_configuration", "lc", map[string]ir.Value{
		"resource_arn": {Raw: nil, Known: false, Span: spanAt(2), Ref: "aws_wafv2_web_acl.acl.arn"},
	})
	if got := checkAll(rule, vuln, logging); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test614_AppSyncNoLogging(t *testing.T) {
	rule := appsyncNoLogging{}
	vuln := res("aws_appsync_graphql_api", "api", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_appsync_graphql_api", "api", map[string]ir.Value{
		"log_config": blks(2, blk("field_log_level", ks("ALL", 2))),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test615_MQNoAuditLogging(t *testing.T) {
	rule := mqNoAuditLogging{}
	vuln := res("aws_mq_broker", "mq", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_mq_broker", "mq", map[string]ir.Value{
		"logs": blks(2, blk("audit", kv(true, 2))),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test617_CodeBuildNoLogging(t *testing.T) {
	rule := codebuildNoLogging{}
	vuln := res("aws_codebuild_project", "cb", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_codebuild_project", "cb", map[string]ir.Value{
		"logs_config": blks(2, blk("cloudwatch_logs", blks(2, blk("status", ks("ENABLED", 2))))),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test618_ESNoAuditLogging(t *testing.T) {
	rule := esNoAuditLogging{}
	vuln := res("aws_elasticsearch_domain", "es", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_elasticsearch_domain", "es", map[string]ir.Value{
		"log_publishing_options": blks(2, blk("log_type", ks("AUDIT_LOGS", 2))),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test620_MQNoGeneralLogging(t *testing.T) {
	rule := mqNoGeneralLogging{}
	vuln := res("aws_mq_broker", "mq", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_mq_broker", "mq", map[string]ir.Value{
		"logs": blks(2, blk("general", kv(true, 2))),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test621_RedshiftNoLogging(t *testing.T) {
	rule := redshiftNoLogging{}
	vuln := res("aws_redshift_cluster", "rs", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_redshift_cluster", "rs", map[string]ir.Value{
		"logging": blks(2, blk("bucket_name", ks("logs", 2))),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test622_MSKNoLogging(t *testing.T) {
	rule := mskNoLogging{}
	vuln := res("aws_msk_cluster", "msk", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_msk_cluster", "msk", map[string]ir.Value{
		"logging_info": blks(2, blk("broker_logs", blks(2, blk("enabled", kv(true, 2))))),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test623_ESNoDomainLogging(t *testing.T) {
	rule := esNoDomainLogging{}
	vuln := res("aws_opensearch_domain", "os", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_opensearch_domain", "os", map[string]ir.Value{
		"log_publishing_options": blks(2, blk("log_type", ks("INDEX_SLOW_LOGS", 2))),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test624_DocDBNoLogging(t *testing.T) {
	rule := docdbNoLogging{}
	vuln := res("aws_docdb_cluster", "d", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_docdb_cluster", "d", map[string]ir.Value{
		"enabled_cloudwatch_logs_exports": strList(2, "audit", "profiler"),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test625_CloudFrontNoLogging(t *testing.T) {
	rule := cloudfrontNoLogging{}
	vuln := res("aws_cloudfront_distribution", "cf", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_cloudfront_distribution", "cf", map[string]ir.Value{
		"logging_config": blks(2, blk("bucket", ks("logs", 2))),
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}

func Test626_DocDBShortBackup(t *testing.T) {
	rule := docdbShortBackup{}
	vuln := res("aws_docdb_cluster", "d", map[string]ir.Value{})
	if got := runRule(rule, vuln); len(got) != 1 {
		t.Errorf("vulnerable: want 1 finding, got %d", len(got))
	}
	ok := res("aws_docdb_cluster", "d", map[string]ir.Value{
		"backup_retention_period": {Raw: float64(14), Known: true, Span: spanAt(2)},
	})
	if got := runRule(rule, ok); len(got) != 0 {
		t.Errorf("compliant: want 0 findings, got %d", len(got))
	}
}
