package aws

import (
	"strings"

	"aegis/internal/ir"
)

// Final gap-closure rules (AEGIS-AWS-541–544): Checkov-parity checks to close
// the remaining detection gap.
//
// OVERLAP NOTES:
//   - 540 (engine-scoped RDS IAM-auth variant) was removed in Sprint 2
//     as an exact duplicate of AEGIS-AWS-311 on mysql/postgres
//     instances; 540's engine scoping was ported into 311, which now
//     fires only on engines that support IAM database authentication.
//   - 541 targets aws_launch_configuration, which AEGIS-AWS-204
//     (ec2NoIMDSv2) does NOT cover (204 handles aws_instance and
//     aws_launch_template). Implementing 541 on aws_instance would
//     duplicate 204 exactly.

// ---------------------------------------------------------------------------
// AEGIS-AWS-540: RDS without IAM authentication (mysql/postgres) (CKV_AWS_161)

// ---------------------------------------------------------------------------
// AEGIS-AWS-541: Launch configuration allows IMDSv1 (CKV_AWS_79)
// ---------------------------------------------------------------------------

type launchConfigNoIMDSv2 struct{}

func (launchConfigNoIMDSv2) ID() string { return "AEGIS-AWS-541" }
func (launchConfigNoIMDSv2) Title() string {
	return "Launch configuration allows IMDSv1"
}
func (launchConfigNoIMDSv2) Description() string {
	return "Without metadata_options.http_tokens = \"required\", instances " +
		"launched from this configuration accept IMDSv1 requests, which SSRF " +
		"vulnerabilities can abuse to steal credentials. AEGIS-AWS-204 covers " +
		"aws_instance and aws_launch_template; this rule closes the gap for " +
		"aws_launch_configuration."
}
func (launchConfigNoIMDSv2) Severity() ir.Severity { return ir.SeverityHigh }
func (launchConfigNoIMDSv2) AppliesTo(resType string) bool {
	return resType == "aws_launch_configuration"
}

func (launchConfigNoIMDSv2) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "metadata_options")
	if present && !known {
		return nil // unresolved block: cannot decide
	}
	mk := func(actual string) []ir.Finding {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-541",
			Title:       (launchConfigNoIMDSv2{}).Title(),
			Description: (launchConfigNoIMDSv2{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "metadata_options.http_tokens",
				Span:      evidenceSpan(span, r.Span),
				Actual:    actual,
				Expected:  "metadata_options { http_tokens = \"required\" }",
			},
		}}
	}
	if !present || len(blks) == 0 {
		return mk("absent (provider default allows IMDSv1)")
	}
	for _, b := range blks {
		tokens, _, tpresent, tknown := blockString(b, "http_tokens")
		if tpresent && !tknown {
			return nil // unresolved: cannot decide
		}
		if !tpresent {
			return mk("absent (provider default allows IMDSv1)")
		}
		if strings.EqualFold(strings.TrimSpace(tokens), "required") {
			return nil // IMDSv2 enforced
		}
		return mk(tokens)
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-542: Lambda function not in VPC (CKV_AWS_117)
// ---------------------------------------------------------------------------

type lambdaNoVPC struct{}

func (lambdaNoVPC) ID() string    { return "AEGIS-AWS-542" }
func (lambdaNoVPC) Title() string { return "Lambda function not deployed in a VPC" }
func (lambdaNoVPC) Description() string {
	return "Lambda functions without a vpc_config block run outside your VPC, " +
		"with no security-group or network-ACL control over their network " +
		"access. Functions accessing VPC resources (RDS, ElastiCache) should " +
		"declare vpc_config with subnet_ids and security_group_ids."
}
func (lambdaNoVPC) Severity() ir.Severity { return ir.SeverityLow }
func (lambdaNoVPC) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}

func (lambdaNoVPC) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "vpc_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil // vpc_config declared
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-542",
		Title:       (lambdaNoVPC{}).Title(),
		Description: (lambdaNoVPC{}).Description(),
		Severity:    ir.SeverityLow,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "vpc_config",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "absent",
			Expected:  "vpc_config block with subnet_ids and security_group_ids",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-543: RDS instance without CloudWatch log exports (CKV_AWS_129)
// ---------------------------------------------------------------------------

type rdsNoLogExports struct{}

func (rdsNoLogExports) ID() string { return "AEGIS-AWS-543" }
func (rdsNoLogExports) Title() string {
	return "RDS instance without CloudWatch log exports"
}
func (rdsNoLogExports) Description() string {
	return "Hygiene: RDS instances should export database logs to CloudWatch " +
		"via enabled_cloudwatch_logs_exports for auditing and troubleshooting. " +
		"Without log exports, forensic analysis after an incident is limited."
}
func (rdsNoLogExports) Severity() ir.Severity { return ir.SeverityLow }
func (rdsNoLogExports) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}

func (rdsNoLogExports) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attr("enabled_cloudwatch_logs_exports")
	if !ok {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-543",
			(rdsNoLogExports{}).Title(), (rdsNoLogExports{}).Description(),
			r, "enabled_cloudwatch_logs_exports", r.Span, "absent",
			"enabled_cloudwatch_logs_exports with engine log types")}
	}
	if !v.Known {
		return nil
	}
	if l, ok := v.AsList(); ok && len(l) == 0 {
		return []ir.Finding{hygieneFinding("AEGIS-AWS-543",
			(rdsNoLogExports{}).Title(), (rdsNoLogExports{}).Description(),
			r, "enabled_cloudwatch_logs_exports", v.Span, "empty list",
			"enabled_cloudwatch_logs_exports with engine log types")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-544: RDS instance without auto minor version upgrades (CKV_AWS_226)
// ---------------------------------------------------------------------------

type rdsNoAutoMinorUpgrade struct{}

func (rdsNoAutoMinorUpgrade) ID() string { return "AEGIS-AWS-544" }
func (rdsNoAutoMinorUpgrade) Title() string {
	return "RDS instance without auto minor version upgrades"
}
func (rdsNoAutoMinorUpgrade) Description() string {
	return "Hygiene: RDS instances should enable auto_minor_version_upgrade " +
		"so security patches are applied automatically during maintenance " +
		"windows. Without it, the engine can drift behind on security fixes."
}
func (rdsNoAutoMinorUpgrade) Severity() ir.Severity { return ir.SeverityLow }
func (rdsNoAutoMinorUpgrade) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}

func (rdsNoAutoMinorUpgrade) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "auto_minor_version_upgrade")
	if present && !known {
		return nil
	}
	if !present {
		// Absent: the AWS API and Terraform provider default is TRUE,
		// so absent means upgrades ARE applied. Only explicit false fires.
		return nil
	}
	if val {
		return nil
	}
	return []ir.Finding{hygieneFinding("AEGIS-AWS-544",
		(rdsNoAutoMinorUpgrade{}).Title(), (rdsNoAutoMinorUpgrade{}).Description(),
		r, "auto_minor_version_upgrade", evidenceSpan(span, r.Span), "false",
		"auto_minor_version_upgrade = true")}
}

// FinalGapRules returns the gap-closure rules in ID order.
func FinalGapRules() []ir.Rule {
	return []ir.Rule{
		launchConfigNoIMDSv2{},  // AEGIS-AWS-541
		lambdaNoVPC{},           // AEGIS-AWS-542
		rdsNoLogExports{},       // AEGIS-AWS-543
		rdsNoAutoMinorUpgrade{}, // AEGIS-AWS-544
	}
}
