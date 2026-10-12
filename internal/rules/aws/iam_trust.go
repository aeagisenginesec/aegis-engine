package aws

import (
	"encoding/json"
	"sort"
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-101: IAM role assumable by anyone
// ---------------------------------------------------------------------------

type iamRoleOpenTrust struct{}

func (iamRoleOpenTrust) ID() string { return "AEGIS-AWS-101" }
func (iamRoleOpenTrust) Title() string {
	return "IAM role assumable by anyone"
}
func (iamRoleOpenTrust) Description() string {
	return "An Allow statement in the trust policy with Principal \"*\" " +
		"lets any AWS identity assume this role. Restrict the principal to " +
		"specific accounts, roles, or services."
}
func (iamRoleOpenTrust) Severity() ir.Severity { return ir.SeverityCritical }

func (iamRoleOpenTrust) AppliesTo(resType string) bool {
	return resType == "aws_iam_role"
}

// Check evaluates one role; the engine prefers CheckAll for
// CrossResourceRules, but Check stays correct for direct use.
func (r iamRoleOpenTrust) Check(res ir.Resource) []ir.Finding {
	return checkRoleOpenTrust(res)
}

func (iamRoleOpenTrust) CheckAll(resources []ir.Resource) []ir.Finding {
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	var out []ir.Finding
	for _, res := range sorted {
		if res.Type != "aws_iam_role" {
			continue
		}
		out = append(out, checkRoleOpenTrust(res)...)
	}
	return out
}

var _ ir.CrossResourceRule = iamRoleOpenTrust{}

func checkRoleOpenTrust(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "assume_role_policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if trustPolicyOpenToAnyone(pol) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-101",
			Title:       (iamRoleOpenTrust{}).Title(),
			Description: (iamRoleOpenTrust{}).Description(),
			Severity:    ir.SeverityCritical,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "assume_role_policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "Allow statement with Principal \"*\"",
				Expected:  "Principal restricted to specific AWS identities",
			},
			Path: []ir.PathStep{{
				Resource: r.Address(),
				Detail:   "any AWS identity can assume this role via the open trust policy",
				Span:     evidenceSpan(span, r.Span),
			}},
		}}
	}
	return nil
}

// trustPolicyOpenToAnyone parses a trust-policy JSON document and reports
// whether any Allow statement grants Principal "*". A statement carrying a
// Condition is skipped: the condition may legitimately scope the wildcard
// (e.g. aws:PrincipalOrgID), so we cannot prove it is open. Malformed JSON
// or unexpected shapes yield false (cannot decide -> no finding).
func trustPolicyOpenToAnyone(doc string) bool {
	for _, s := range policyStatements(doc) {
		if s["Effect"] != "Allow" {
			continue
		}
		if _, hasCond := s["Condition"]; hasCond {
			continue
		}
		if _, hasNotPrincipal := s["NotPrincipal"]; hasNotPrincipal {
			continue
		}
		if principalAllowsAnyone(s["Principal"]) {
			return true
		}
	}
	return false
}

// principalAllowsAnyone reports whether a Principal value grants access to
// everyone: the string "*" or a map with an AWS key of "*" (string or list).
// Service/federated principals are not anonymous and do not match.
func principalAllowsAnyone(p any) bool {
	switch t := p.(type) {
	case string:
		return strings.TrimSpace(t) == "*"
	case map[string]any:
		for k, v := range t {
			if strings.EqualFold(k, "AWS") && stringOrListHasStar(v) {
				return true
			}
		}
	}
	return false
}

// policyStatements parses the Statement element of an IAM policy document,
// accepting a single object or a list. Anything unparseable yields nil.
func policyStatements(doc string) []map[string]any {
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return nil
	}
	if len(parsed.Statement) == 0 {
		return nil
	}
	if parsed.Statement[0] == '[' {
		var stmts []map[string]any
		if err := json.Unmarshal(parsed.Statement, &stmts); err != nil {
			return nil
		}
		return stmts
	}
	var one map[string]any
	if err := json.Unmarshal(parsed.Statement, &one); err != nil {
		return nil
	}
	return []map[string]any{one}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-102: IAM managed policy grants administrative access
// ---------------------------------------------------------------------------

type iamAdminManagedPolicy struct{}

func (iamAdminManagedPolicy) ID() string { return "AEGIS-AWS-102" }
func (iamAdminManagedPolicy) Title() string {
	return "IAM managed policy grants administrative access"
}
func (iamAdminManagedPolicy) Description() string {
	return "An Allow statement with Action \"*\" (or \"iam:*\") on Resource " +
		"\"*\" is administrative access in a customer-managed policy. Scope " +
		"actions and resources to least privilege."
}
func (iamAdminManagedPolicy) Severity() ir.Severity { return ir.SeverityHigh }

func (iamAdminManagedPolicy) AppliesTo(resType string) bool {
	return resType == "aws_iam_policy"
}

func (r iamAdminManagedPolicy) Check(res ir.Resource) []ir.Finding {
	return checkAdminManagedPolicy(res)
}

func (iamAdminManagedPolicy) CheckAll(resources []ir.Resource) []ir.Finding {
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	var out []ir.Finding
	for _, res := range sorted {
		if res.Type != "aws_iam_policy" {
			continue
		}
		out = append(out, checkAdminManagedPolicy(res)...)
	}
	return out
}

var _ ir.CrossResourceRule = iamAdminManagedPolicy{}

func checkAdminManagedPolicy(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if managedPolicyIsAdmin(pol) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-102",
			Title:       (iamAdminManagedPolicy{}).Title(),
			Description: (iamAdminManagedPolicy{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "Allow statement with Action \"*\"/\"iam:*\" on Resource \"*\"",
				Expected:  "scoped Action and Resource lists",
			},
			Path: []ir.PathStep{{
				Resource: r.Address(),
				Detail:   "any identity attached to this policy gains administrative access",
				Span:     evidenceSpan(span, r.Span),
			}},
		}}
	}
	return nil
}

// managedPolicyIsAdmin reports whether any Allow statement has Action "*"
// or "iam:*" on Resource "*". Action may be a string or a list. Statements
// with NotAction are skipped (cannot decide). Malformed JSON yields false.
func managedPolicyIsAdmin(doc string) bool {
	for _, s := range policyStatements(doc) {
		if s["Effect"] != "Allow" {
			continue
		}
		if _, hasNotAction := s["NotAction"]; hasNotAction {
			continue
		}
		if actionIsAdminLike(s["Action"]) && stringOrListHasStar(s["Resource"]) {
			return true
		}
	}
	return false
}

// actionIsAdminLike reports whether v is "*" or "iam:*", or a list
// containing either (case-insensitive, trimmed).
func actionIsAdminLike(v any) bool {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		return s == "*" || strings.EqualFold(s, "iam:*")
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok {
				s = strings.TrimSpace(s)
				if s == "*" || strings.EqualFold(s, "iam:*") {
					return true
				}
			}
		}
	}
	return false
}
