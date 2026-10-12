package aws

import (
	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-010: CloudTrail without log file validation
// ---------------------------------------------------------------------------

type cloudtrailNoValidation struct{}

func (cloudtrailNoValidation) ID() string    { return "AEGIS-AWS-010" }
func (cloudtrailNoValidation) Title() string { return "CloudTrail without log file validation" }
func (cloudtrailNoValidation) Description() string {
	return "Log file validation detects tampering with CloudTrail logs " +
		"after delivery. The provider default for enable_log_file_validation " +
		"is false, so an absent attribute is a finding."
}
func (cloudtrailNoValidation) Severity() ir.Severity { return ir.SeverityMedium }

func (cloudtrailNoValidation) AppliesTo(resType string) bool { return resType == "aws_cloudtrail" }

func (cloudtrailNoValidation) Check(r ir.Resource) []ir.Finding {
	val, span, present, known := getBool(r, "enable_log_file_validation")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && val {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-010",
		Title:       (cloudtrailNoValidation{}).Title(),
		Description: (cloudtrailNoValidation{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enable_log_file_validation",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "true",
		},
	}}
}
