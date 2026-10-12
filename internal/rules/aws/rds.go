package aws

import (
	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-007: RDS instance without storage encryption
// ---------------------------------------------------------------------------

type rdsUnencrypted struct{}

func (rdsUnencrypted) ID() string    { return "AEGIS-AWS-007" }
func (rdsUnencrypted) Title() string { return "RDS instance without storage encryption" }
func (rdsUnencrypted) Description() string {
	return "RDS storage should be encrypted at rest. The provider default " +
		"for storage_encrypted is false, so an absent attribute is a finding."
}
func (rdsUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }

func (rdsUnencrypted) AppliesTo(resType string) bool { return resType == "aws_db_instance" }

func (rdsUnencrypted) Check(r ir.Resource) []ir.Finding {
	enc, span, present, known := getBool(r, "storage_encrypted")
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
		RuleID:      "AEGIS-AWS-007",
		Title:       (rdsUnencrypted{}).Title(),
		Description: (rdsUnencrypted{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "storage_encrypted",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-008: RDS instance without deletion protection
// ---------------------------------------------------------------------------

type rdsNoDeletionProtection struct{}

func (rdsNoDeletionProtection) ID() string    { return "AEGIS-AWS-008" }
func (rdsNoDeletionProtection) Title() string { return "RDS instance without deletion protection" }
func (rdsNoDeletionProtection) Description() string {
	return "Deletion protection guards against accidental database " +
		"destruction. The provider default is false."
}
func (rdsNoDeletionProtection) Severity() ir.Severity { return ir.SeverityMedium }

func (rdsNoDeletionProtection) AppliesTo(resType string) bool { return resType == "aws_db_instance" }

func (rdsNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	prot, span, present, known := getBool(r, "deletion_protection")
	if present && !known {
		return nil
	}
	if present && prot {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-008",
		Title:       (rdsNoDeletionProtection{}).Title(),
		Description: (rdsNoDeletionProtection{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "deletion_protection",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  "true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-011: RDS instance publicly accessible
// ---------------------------------------------------------------------------

type rdsPublic struct{}

func (rdsPublic) ID() string    { return "AEGIS-AWS-011" }
func (rdsPublic) Title() string { return "RDS instance publicly accessible" }
func (rdsPublic) Description() string {
	return "A publicly accessible database accepts connections from the " +
		"internet. Keep databases in private subnets with publicly_accessible " +
		"false (the provider default)."
}
func (rdsPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (rdsPublic) AppliesTo(resType string) bool { return resType == "aws_db_instance" }

func (rdsPublic) Check(r ir.Resource) []ir.Finding {
	pub, span, present, known := getBool(r, "publicly_accessible")
	if !present || !known {
		return nil // default false; unresolved cannot be decided
	}
	if !pub {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-011",
		Title:       (rdsPublic{}).Title(),
		Description: (rdsPublic{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "publicly_accessible",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false",
		},
	}}
}
