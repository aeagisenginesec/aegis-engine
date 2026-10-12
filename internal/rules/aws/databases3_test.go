package aws

import (
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-631: RDS Cluster without audit logging
// ---------------------------------------------------------------------------

func Test631_AuroraNoAuditLoggingFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"enabled_cloudwatch_logs_exports": strList(3)},
		{"enabled_cloudwatch_logs_exports": strList(3, "error", "general")},
	} {
		fs := runRule(auroraNoAuditLogging{}, res("aws_rds_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1 (attrs=%v)", len(fs), attrs)
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test631_AuroraAuditLoggingQuiet(t *testing.T) {
	fs := runRule(auroraNoAuditLogging{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"enabled_cloudwatch_logs_exports": strList(3, "audit", "error")}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test631_AuroraAuditLoggingUnknownQuiet(t *testing.T) {
	fs := runRule(auroraNoAuditLogging{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"enabled_cloudwatch_logs_exports": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-632: Aurora cluster without backtracking enabled
// ---------------------------------------------------------------------------

func Test632_AuroraNoBacktrackingFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{"engine": ks("aurora-mysql", 2)},
		{"engine": ks("aurora-mysql", 2), "backtrack_window": kn(0, 3)},
		{"engine": ks("Aurora-MySQL", 2)}, // engine match is case-insensitive
	} {
		fs := runRule(auroraNoBacktracking{}, res("aws_rds_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1 (attrs=%v)", len(fs), attrs)
		}
		if fs[0].Severity != ir.SeverityLow {
			t.Fatalf("want low severity, got %s", fs[0].Severity)
		}
	}
}

func Test632_AuroraBacktrackingEnabledQuiet(t *testing.T) {
	fs := runRule(auroraNoBacktracking{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"engine": ks("aurora-mysql", 2), "backtrack_window": kn(86400, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test632_AuroraNonMySQLEngineQuiet(t *testing.T) {
	// Backtracking is Aurora MySQL-only: postgres engines must not be flagged.
	// Absent engine fires for Checkov parity (defaults to Aurora-compatible).
	fs := runRule(auroraNoBacktracking{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"engine": ks("aurora-postgresql", 2)}))
	if len(fs) != 0 {
		t.Fatalf("postgres: got %d findings, want 0", len(fs))
	}
	// Absent engine: fire (Checkov parity)
	fs = runRule(auroraNoBacktracking{}, res("aws_rds_cluster", "main", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("absent engine: got %d findings, want 1", len(fs))
	}
}

func Test632_AuroraBacktrackWindowUnknownQuiet(t *testing.T) {
	fs := runRule(auroraNoBacktracking{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"engine": ks("aurora-mysql", 2), "backtrack_window": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-633: RDS Cluster not configured to copy tags to snapshots
// ---------------------------------------------------------------------------

func Test633_AuroraNoCopyTagsFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"copy_tags_to_snapshot": kv(false, 3)},
	} {
		fs := runRule(auroraNoCopyTagsSnapshot{}, res("aws_rds_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityLow {
			t.Fatalf("want low severity, got %s", fs[0].Severity)
		}
	}
}

func Test633_AuroraCopyTagsQuiet(t *testing.T) {
	fs := runRule(auroraNoCopyTagsSnapshot{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"copy_tags_to_snapshot": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test633_AuroraCopyTagsUnknownQuiet(t *testing.T) {
	fs := runRule(auroraNoCopyTagsSnapshot{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"copy_tags_to_snapshot": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-634: RDS Cluster not encrypted with customer-managed KMS key
// ---------------------------------------------------------------------------

func Test634_AuroraNoCMKFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{"storage_encrypted": kv(true, 2)},
		{"storage_encrypted": kv(true, 2), "kms_key_id": ks("", 3)},
	} {
		fs := runRule(auroraNoCMK{}, res("aws_rds_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1 (attrs=%v)", len(fs), attrs)
		}
		if fs[0].Severity != ir.SeverityHigh {
			t.Fatalf("want high severity, got %s", fs[0].Severity)
		}
	}
}

func Test634_AuroraCMKSetQuiet(t *testing.T) {
	fs := runRule(auroraNoCMK{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{
			"storage_encrypted": kv(true, 2),
			"kms_key_id":        ks("arn:aws:kms:us-east-1:123456789012:key/abcd-1234", 3),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test634_AuroraUnencryptedNotCMKQuiet(t *testing.T) {
	// Checkov CKV_AWS_327 parity: fire when kms_key_id is absent, regardless
	// of storage_encrypted state. An unencrypted cluster is also not using a CMK.
	for _, attrs := range []map[string]ir.Value{
		{},
		{"storage_encrypted": kv(false, 2)},
		{"storage_encrypted": kv(true, 2)},
	} {
		fs := runRule(auroraNoCMK{}, res("aws_rds_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1 (no CMK)", len(fs))
		}
	}
}

func Test634_AuroraKMSUnknownQuiet(t *testing.T) {
	fs := runRule(auroraNoCMK{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"storage_encrypted": kv(true, 2), "kms_key_id": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-635: RDS Cluster without Performance Insights
// ---------------------------------------------------------------------------

func Test635_AuroraNoPerfInsightsFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"performance_insights_enabled": kv(false, 3)},
	} {
		fs := runRule(auroraNoPerfInsights{}, res("aws_rds_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test635_AuroraPerfInsightsQuiet(t *testing.T) {
	fs := runRule(auroraNoPerfInsights{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"performance_insights_enabled": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test635_AuroraPerfInsightsUnknownQuiet(t *testing.T) {
	fs := runRule(auroraNoPerfInsights{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"performance_insights_enabled": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-636: RDS Cluster without enhanced monitoring
// ---------------------------------------------------------------------------

func Test636_AuroraNoEnhancedMonitoringFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"monitoring_interval": kn(0, 3)},
	} {
		fs := runRule(auroraNoEnhancedMonitoring{}, res("aws_rds_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test636_AuroraEnhancedMonitoringQuiet(t *testing.T) {
	fs := runRule(auroraNoEnhancedMonitoring{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"monitoring_interval": kn(60, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test636_AuroraMonitoringIntervalUnknownQuiet(t *testing.T) {
	fs := runRule(auroraNoEnhancedMonitoring{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"monitoring_interval": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}
