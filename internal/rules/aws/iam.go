package aws

import (
	"encoding/json"
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
				Actual:    "Allow statement with Action \"*\" on Resource \"*\"",
				Expected:  "scoped Action and Resource lists",
			},
		}}
	}
	return nil
}

// iamStatementIsAdmin parses a policy JSON document and reports whether any
// Allow statement has Action "*" with Resource "*". Action and Resource may
// each be a string or a list. Malformed JSON or unexpected shapes yield
// false (cannot decide -> no finding).
func iamStatementIsAdmin(doc string) bool {
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return false
	}
	if len(parsed.Statement) == 0 {
		return false
	}
	var stmts []map[string]any
	if parsed.Statement[0] == '[' {
		if err := json.Unmarshal(parsed.Statement, &stmts); err != nil {
			return false
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal(parsed.Statement, &one); err != nil {
			return false
		}
		stmts = []map[string]any{one}
	}
	for _, s := range stmts {
		eff, _ := s["Effect"].(string)
		if eff != "Allow" {
			continue
		}
		if stringOrListHasStar(s["Action"]) && stringOrListHasStar(s["Resource"]) {
			return true
		}
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
