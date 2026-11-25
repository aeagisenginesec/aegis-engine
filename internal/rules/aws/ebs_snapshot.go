// Package aws — EBS snapshot sharing (AEGIS-AWS-860).
//
// An EBS snapshot shared with group "all" is public: anyone with the
// snapshot ID can create a volume from it and read the data. There is no
// Checkov equivalent — this is a pure Aegis lead.
package aws

import (
	"strings"

	"aegis/internal/ir"
)

// EBSSnapshotRules returns the EBS snapshot sharing rule (AEGIS-AWS-860).
func EBSSnapshotRules() []ir.Rule {
	return []ir.Rule{ebsSnapshotPublic{}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-860: EBS snapshot shared with everyone (group all)
// ---------------------------------------------------------------------------

type ebsSnapshotPublic struct{}

func (ebsSnapshotPublic) ID() string { return "AEGIS-AWS-860" }
func (ebsSnapshotPublic) Title() string {
	return "EBS snapshot shared with everyone (group all)"
}
func (ebsSnapshotPublic) Description() string {
	return "aws_snapshot_create_volume_permission with group = \"all\" " +
		"shares the EBS snapshot with every AWS account: anyone can " +
		"create a volume from it and read the data. Share snapshots " +
		"only with specific account IDs."
}
func (ebsSnapshotPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (ebsSnapshotPublic) AppliesTo(resType string) bool {
	return resType == "aws_snapshot_create_volume_permission"
}

func (ebsSnapshotPublic) Check(r ir.Resource) []ir.Finding {
	rule := ebsSnapshotPublic{}
	group, span, present, known := getString(r, "group")
	if !present || !known {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(group), "all") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "group",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "group = \"all\"",
			Expected:  "share with specific AWS account IDs only",
		},
	}}
}
