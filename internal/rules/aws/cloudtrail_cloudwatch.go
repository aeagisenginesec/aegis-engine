// Package aws — CloudTrail without CloudWatch Logs integration (AEGIS-AWS-851).
//
// Trivy parity gap: Trivy AVD-AWS-0162 fires on CloudTrail trails that do
// not deliver to CloudWatch Logs, and Aegis had no equivalent rule.
// CIS AWS Foundations Benchmark 3.4 requires the integration because
// CloudWatch Logs enables near-real-time alerting on API activity
// (e.g. alarms on ConsoleLogin failures, root usage, or policy changes),
// while S3-only delivery leaves detection delayed by log delivery and
// Athena/query latency. Both the log group ARN and the role ARN are
// required for the integration to function, so a trail with either one
// missing (or only one set) is reported. Severity Low: S3 delivery still
// captures the events, so this is a detection-latency gap, not data loss.
package aws

import (
	"strings"

	"aegis/internal/ir"
)

// CloudTrailCloudWatchRules returns CloudTrail/CloudWatch rules in ID order.
func CloudTrailCloudWatchRules() []ir.Rule {
	return []ir.Rule{
		cloudtrailNoCloudWatch{}, // AEGIS-AWS-851
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-851: CloudTrail trail without CloudWatch Logs integration
// ---------------------------------------------------------------------------

type cloudtrailNoCloudWatch struct{}

func (cloudtrailNoCloudWatch) ID() string { return "AEGIS-AWS-851" }
func (cloudtrailNoCloudWatch) Title() string {
	return "CloudTrail trail without CloudWatch Logs integration"
}
func (cloudtrailNoCloudWatch) Description() string {
	return "A CloudTrail trail that does not deliver to CloudWatch Logs " +
		"cannot feed real-time metric filters and alarms on API activity. " +
		"Set both cloud_watch_logs_group_arn and cloud_watch_logs_role_arn " +
		"so suspicious events (console logins, root usage, policy changes) " +
		"alert within minutes instead of waiting on S3 log delivery."
}
func (cloudtrailNoCloudWatch) Severity() ir.Severity { return ir.SeverityLow }
func (cloudtrailNoCloudWatch) AppliesTo(resType string) bool {
	return resType == "aws_cloudtrail"
}

func (cloudtrailNoCloudWatch) Check(r ir.Resource) []ir.Finding {
	group, _, groupPresent, groupKnown := getString(r, "cloud_watch_logs_group_arn")
	role, _, rolePresent, roleKnown := getString(r, "cloud_watch_logs_role_arn")
	if (groupPresent && !groupKnown) || (rolePresent && !roleKnown) {
		return nil // unresolved: cannot decide
	}
	groupSet := groupPresent && strings.TrimSpace(group) != ""
	roleSet := rolePresent && strings.TrimSpace(role) != ""
	if groupSet && roleSet {
		return nil // integrated
	}
	missing := "cloud_watch_logs_group_arn"
	if groupSet {
		missing = "cloud_watch_logs_role_arn"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-851",
		Title:       (cloudtrailNoCloudWatch{}).Title(),
		Description: (cloudtrailNoCloudWatch{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: missing,
			Span:      evidenceSpan(ir.Span{}, r.Span),
			Actual:    "absent (no CloudWatch Logs integration)",
			Expected:  "both cloud_watch_logs_group_arn and cloud_watch_logs_role_arn set",
		},
	}}
}
