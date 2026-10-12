package aws

import (
	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-009: EBS volume without encryption
// ---------------------------------------------------------------------------

type ebsUnencrypted struct{}

func (ebsUnencrypted) ID() string    { return "AEGIS-AWS-009" }
func (ebsUnencrypted) Title() string { return "EBS volume without encryption" }
func (ebsUnencrypted) Description() string {
	return "EBS volumes should be encrypted at rest. The provider default " +
		"for encrypted is false, so an absent attribute is a finding."
}
func (ebsUnencrypted) Severity() ir.Severity { return ir.SeverityMedium }

func (ebsUnencrypted) AppliesTo(resType string) bool { return resType == "aws_ebs_volume" }

func (ebsUnencrypted) Check(r ir.Resource) []ir.Finding {
	enc, span, present, known := getBool(r, "encrypted")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && enc {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-009",
		Title:       (ebsUnencrypted{}).Title(),
		Description: (ebsUnencrypted{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "encrypted",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "true",
		},
	}}
}
