package aws

import (
	"strings"

	"aegis/internal/ir"
)

// Databases3Rules returns the Aurora coverage-gap rules, AEGIS-AWS-631..636,
// in ID order.
func Databases3Rules() []ir.Rule {
	return []ir.Rule{
		auroraNoAuditLogging{},       // AEGIS-AWS-631
		auroraNoBacktracking{},       // AEGIS-AWS-632
		auroraNoCopyTagsSnapshot{},   // AEGIS-AWS-633
		auroraNoCMK{},                // AEGIS-AWS-634
		auroraNoPerfInsights{},       // AEGIS-AWS-635
		auroraNoEnhancedMonitoring{}, // AEGIS-AWS-636
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-631: RDS Cluster without audit logging
// ---------------------------------------------------------------------------

type auroraNoAuditLogging struct{}

func (auroraNoAuditLogging) ID() string { return "AEGIS-AWS-631" }
func (auroraNoAuditLogging) Title() string {
	return "RDS Cluster without audit logging"
}
func (auroraNoAuditLogging) Description() string {
	return "An Aurora cluster whose enabled_cloudwatch_logs_exports does not " +
		"include audit logging has no record of database authentication and " +
		"query activity, leaving malicious or anomalous access undetectable."
}
func (auroraNoAuditLogging) Severity() ir.Severity { return ir.SeverityMedium }

func (auroraNoAuditLogging) AppliesTo(resType string) bool { return resType == "aws_rds_cluster" }

func (auroraNoAuditLogging) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["enabled_cloudwatch_logs_exports"]
	if !ok {
		return auditLogFinding(r, ir.Span{}, "absent (provider default: no log exports)")
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	l, ok := v.AsList()
	if !ok {
		return nil // unexpected shape: cannot decide
	}
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return nil // unresolved element: cannot decide
		}
		if strings.TrimSpace(s) == "audit" {
			return nil
		}
	}
	return auditLogFinding(r, v.Span, "does not include \"audit\"")
}

func auditLogFinding(r ir.Resource, span ir.Span, actual string) []ir.Finding {
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-631",
		Title:       (auroraNoAuditLogging{}).Title(),
		Description: (auroraNoAuditLogging{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enabled_cloudwatch_logs_exports",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "enabled_cloudwatch_logs_exports includes \"audit\"",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-632: Aurora cluster without backtracking enabled
// ---------------------------------------------------------------------------

type auroraNoBacktracking struct{}

func (auroraNoBacktracking) ID() string { return "AEGIS-AWS-632" }
func (auroraNoBacktracking) Title() string {
	return "Aurora cluster without backtracking enabled"
}
func (auroraNoBacktracking) Description() string {
	return "Aurora MySQL backtracking rewinds the cluster to a point in time " +
		"without a restore; with backtrack_window at 0 it is disabled and " +
		"recovery from bad writes requires a slower snapshot restore."
}
func (auroraNoBacktracking) Severity() ir.Severity { return ir.SeverityLow }

func (auroraNoBacktracking) AppliesTo(resType string) bool { return resType == "aws_rds_cluster" }

func (auroraNoBacktracking) Check(r ir.Resource) []ir.Finding {
	// Backtracking is an Aurora MySQL-only feature. Fire when engine is
	// explicitly aurora-mysql OR when engine is absent (Checkov parity:
	// absent engine on aws_rds_cluster defaults to Aurora-compatible).
	// Skip only when engine is explicitly a non-MySQL engine.
	eng, _, epresent, eknown := getString(r, "engine")
	if epresent && eknown {
		engNorm := strings.ToLower(strings.TrimSpace(eng))
		if engNorm != "aurora-mysql" && engNorm != "aurora" && engNorm != "" {
			// Explicitly non-MySQL engine (e.g., aurora-postgresql) — backtracking N/A
			if strings.Contains(engNorm, "postgres") {
				return nil
			}
		}
	}
	bt, span, present, known := getNumber(r, "backtrack_window")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && bt > 0 {
		return nil
	}
	actual := "absent (provider default: 0, disabled)"
	if present {
		actual = "0 (disabled)"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-632",
		Title:       (auroraNoBacktracking{}).Title(),
		Description: (auroraNoBacktracking{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "backtrack_window",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "backtrack_window > 0 (up to 259200 seconds)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-633: RDS Cluster not configured to copy tags to snapshots
// ---------------------------------------------------------------------------

type auroraNoCopyTagsSnapshot struct{}

func (auroraNoCopyTagsSnapshot) ID() string { return "AEGIS-AWS-633" }
func (auroraNoCopyTagsSnapshot) Title() string {
	return "RDS Cluster not configured to copy tags to snapshots"
}
func (auroraNoCopyTagsSnapshot) Description() string {
	return "With copy_tags_to_snapshot absent or false, snapshots lose the " +
		"cluster's tags, breaking cost allocation, ownership tracking, and " +
		"tag-based access controls on restored data."
}
func (auroraNoCopyTagsSnapshot) Severity() ir.Severity { return ir.SeverityLow }

func (auroraNoCopyTagsSnapshot) AppliesTo(resType string) bool { return resType == "aws_rds_cluster" }

func (auroraNoCopyTagsSnapshot) Check(r ir.Resource) []ir.Finding {
	cp, span, present, known := getBool(r, "copy_tags_to_snapshot")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && cp {
		return nil
	}
	actual := "absent (provider default: no tag copy)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-633",
		Title:       (auroraNoCopyTagsSnapshot{}).Title(),
		Description: (auroraNoCopyTagsSnapshot{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "copy_tags_to_snapshot",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "copy_tags_to_snapshot = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-634: RDS Cluster not encrypted with customer-managed KMS key
// ---------------------------------------------------------------------------

type auroraNoCMK struct{}

func (auroraNoCMK) ID() string { return "AEGIS-AWS-634" }
func (auroraNoCMK) Title() string {
	return "RDS Cluster not encrypted with customer-managed KMS key"
}
func (auroraNoCMK) Description() string {
	return "An encrypted Aurora cluster with no kms_key_id uses the default " +
		"AWS-managed key; a customer-managed key (CMK) gives control over key " +
		"rotation, grants, and audit trail."
}
func (auroraNoCMK) Severity() ir.Severity { return ir.SeverityHigh }

func (auroraNoCMK) AppliesTo(resType string) bool { return resType == "aws_rds_cluster" }

func (auroraNoCMK) Check(r ir.Resource) []ir.Finding {
	// Checkov CKV_AWS_327 parity: fire when kms_key_id is absent, regardless
	// of storage_encrypted state. An unencrypted cluster (covered by 359)
	// is also not using a CMK.
	key, span, kpresent, kknown := getString(r, "kms_key_id")
	if kpresent && !kknown {
		return nil // unresolved: cannot decide
	}
	if kpresent && strings.TrimSpace(key) != "" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-634",
		Title:       (auroraNoCMK{}).Title(),
		Description: (auroraNoCMK{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "kms_key_id",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "absent (provider default: AWS-managed key)",
			Expected:  "kms_key_id set to a customer-managed key",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-635: RDS Cluster without Performance Insights
// ---------------------------------------------------------------------------

type auroraNoPerfInsights struct{}

func (auroraNoPerfInsights) ID() string { return "AEGIS-AWS-635" }
func (auroraNoPerfInsights) Title() string {
	return "RDS Cluster without Performance Insights"
}
func (auroraNoPerfInsights) Description() string {
	return "With performance_insights_enabled absent or false, the cluster " +
		"provides no query-level performance telemetry, slowing detection of " +
		"abusive or anomalous database workloads."
}
func (auroraNoPerfInsights) Severity() ir.Severity { return ir.SeverityMedium }

func (auroraNoPerfInsights) AppliesTo(resType string) bool { return resType == "aws_rds_cluster" }

func (auroraNoPerfInsights) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "performance_insights_enabled")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && en {
		return nil
	}
	actual := "absent (provider default: disabled)"
	if present {
		actual = "false"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-635",
		Title:       (auroraNoPerfInsights{}).Title(),
		Description: (auroraNoPerfInsights{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "performance_insights_enabled",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "performance_insights_enabled = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-636: RDS Cluster without enhanced monitoring
// ---------------------------------------------------------------------------

type auroraNoEnhancedMonitoring struct{}

func (auroraNoEnhancedMonitoring) ID() string { return "AEGIS-AWS-636" }
func (auroraNoEnhancedMonitoring) Title() string {
	return "RDS Cluster without enhanced monitoring"
}
func (auroraNoEnhancedMonitoring) Description() string {
	return "With monitoring_interval at 0 or absent, the cluster emits only " +
		"basic CloudWatch metrics; enhanced monitoring (1-60s granularity) is " +
		"needed to spot OS-level anomalies such as unexpected connections."
}
func (auroraNoEnhancedMonitoring) Severity() ir.Severity { return ir.SeverityMedium }

func (auroraNoEnhancedMonitoring) AppliesTo(resType string) bool { return resType == "aws_rds_cluster" }

func (auroraNoEnhancedMonitoring) Check(r ir.Resource) []ir.Finding {
	mi, span, present, known := getNumber(r, "monitoring_interval")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && mi > 0 {
		return nil
	}
	actual := "absent (provider default: 0, disabled)"
	if present {
		actual = "0 (disabled)"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-636",
		Title:       (auroraNoEnhancedMonitoring{}).Title(),
		Description: (auroraNoEnhancedMonitoring{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "monitoring_interval",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "monitoring_interval between 1 and 60",
		},
	}}
}
