package aws

import (
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-006: IAM policy allows all actions on all resources
// ---------------------------------------------------------------------------

type iamAdminPolicy struct{}

func (iamAdminPolicy) ID() string    { return "AEGIS-AWS-006" }
func (iamAdminPolicy) Title() string { return "IAM policy allows all actions on all resources" }
func (iamAdminPolicy) Description() string {
	return "An Allow statement with Action \"*\" on Resource \"*\" is " +
		"administrative access. Scope actions and resources to least privilege."
}
func (iamAdminPolicy) Severity() ir.Severity { return ir.SeverityCritical }

func (iamAdminPolicy) AppliesTo(resType string) bool {
	return resType == "aws_iam_policy" ||
		resType == "aws_iam_role_policy" ||
		resType == "aws_iam_user_policy" ||
		resType == "aws_iam_group_policy"
}

func (iamAdminPolicy) Check(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if iamStatementIsAdmin(pol) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-006",
			Title:       (iamAdminPolicy{}).Title(),
			Description: (iamAdminPolicy{}).Description(),
			Severity:    ir.SeverityCritical,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    withNote("Allow statement with Action \"*\" on Resource \"*\"", firstAdminStmtNote(pol, true)),
				Expected:  "scoped Action and Resource lists",
			},
		}}
	}
	return nil
}

// iamStatementIsAdmin parses a policy JSON document and reports whether any
// Allow statement has Action "*" with Resource "*". Action and Resource may
// each be a string or a list. A NotAction statement counts as admin when
// its exclusion list leaves the IAM action class intact (see
// iamNormalizedStmt.isAdmin); a NotResource statement counts when its
// exclusion list does not cover "*". Malformed JSON or unexpected shapes
// yield false (cannot decide -> no finding).
func iamStatementIsAdmin(doc string) bool {
	for _, s := range policyStatements(doc) {
		n := normalizeIAMStmt(s)
		if n == nil || !n.grantsStarAction() || !n.grantsOnStar() {
			continue
		}
		return true
	}
	return false
}

// stringOrListHasStar reports whether v is "*" or a list containing "*".
// Non-string elements or other shapes yield false.
func stringOrListHasStar(v any) bool {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t) == "*"
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && strings.TrimSpace(s) == "*" {
				return true
			}
		}
	}
	return false
}
