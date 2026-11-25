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
	if note, open := trustPolicyOpenToAnyoneNote(pol); open {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-101",
			Title:       (iamRoleOpenTrust{}).Title(),
			Description: (iamRoleOpenTrust{}).Description(),
			Severity:    ir.SeverityCritical,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "assume_role_policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    withNote("Allow statement with Principal \"*\"", note),
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
// (e.g. aws:PrincipalOrgID), so we cannot prove it is open. A statement
// with NotAction grants sts:AssumeRole unless its exclusion list covers
// it (see iam_policy_eval.go); a statement with no action element at all
// keeps the historical behavior of counting as a grant. Malformed JSON
// or unexpected shapes yield false (cannot decide -> no finding).
func trustPolicyOpenToAnyone(doc string) bool {
	_, open := trustPolicyOpenToAnyoneNote(doc)
	return open
}

// trustPolicyOpenToAnyoneNote is trustPolicyOpenToAnyone plus the
// exclusion note of the granting statement ("" when the grant uses plain
// Action), so the finding's evidence names the scope the policy
// explicitly excludes.
func trustPolicyOpenToAnyoneNote(doc string) (string, bool) {
	for _, s := range policyStatements(doc) {
		if lookupMapFold(s, "Condition") != nil {
			continue
		}
		if lookupMapFold(s, "NotPrincipal") != nil {
			continue
		}
		n := normalizeIAMStmt(s)
		if n == nil {
			continue
		}
		if n.hasNotAction && !n.grantsAction("sts:assumerole") {
			continue // AssumeRole is explicitly excluded
		}
		if principalAllowsAnyone(lookupMapFold(s, "Principal")) {
			return n.exclusionNote(), true
		}
	}
	return "", false
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
//
// NotAction/NotResource are returned verbatim in the statement maps; they
// are evaluated with policy-evaluation semantics by normalizeIAMStmt
// (iam_policy_eval.go), which every rule built on this parser now uses.
// A statement with NotAction grants every action its exclusion list does
// not cover; a statement with NotResource grants on every resource its
// exclusion list does not cover. There is no silent skip anymore: see
// the v2.4.0 entry in CHANGELOG.md.
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
				Actual:    withNote("Allow statement with Action \"*\"/\"iam:*\" on Resource \"*\"", firstAdminStmtNote(pol, false)),
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

// managedPolicyIsAdmin reports whether any Allow statement grants
// administrative access: Action "*" or "iam:*" on Resource "*". A
// NotAction statement counts as admin when its exclusion list leaves the
// IAM action class intact (see iamNormalizedStmt.isAdmin); a NotResource
// statement counts when its exclusion list does not cover "*".
// Malformed JSON yields false.
func managedPolicyIsAdmin(doc string) bool {
	for _, s := range policyStatements(doc) {
		n := normalizeIAMStmt(s)
		if n == nil || !n.isAdmin() || !n.grantsOnStar() {
			continue
		}
		return true
	}
	return false
}
