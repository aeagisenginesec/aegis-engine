package aws

import (
	"encoding/json"
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// Tier 1: IAM privilege escalation analysis (AEGIS-AWS-501..505)
//
// These rules analyze IAM policy *semantics* for privilege escalation paths,
// not just blanket "*" permissions (which is AEGIS-AWS-006's territory).
// They mirror Checkov's CKV_AWS_286..290 checks.
//
// Shared helpers below parse a policy document into normalized Allow
// statements. Unparseable documents, unknown values, and statements using
// NotAction/NotResource yield no findings (cannot decide -> silent).
// ---------------------------------------------------------------------------

// iamAllowStmt is one normalized Allow statement: the actions it grants and
// the resources it grants them on. Actions are lower-cased for matching
// (IAM actions are case-insensitive).
type iamAllowStmt struct {
	actions   []string
	resources []string
}

// parseIAMAllowStatements extracts Allow statements from a policy JSON
// document. Returns nil when the document cannot be parsed or has no
// usable Allow statements. Statements using NotAction/NotResource are
// skipped (their semantics require the full action space to evaluate).
func parseIAMAllowStatements(doc string) []iamAllowStmt {
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return nil
	}
	if len(parsed.Statement) == 0 {
		return nil
	}
	var raw []map[string]any
	if len(parsed.Statement) > 0 && parsed.Statement[0] == '[' {
		if err := json.Unmarshal(parsed.Statement, &raw); err != nil {
			return nil
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal(parsed.Statement, &one); err != nil {
			return nil
		}
		raw = []map[string]any{one}
	}
	var out []iamAllowStmt
	for _, s := range raw {
		eff, _ := s["Effect"].(string)
		if !strings.EqualFold(strings.TrimSpace(eff), "Allow") {
			continue
		}
		// NotAction/NotResource: cannot evaluate safely -> skip statement.
		if _, ok := s["NotAction"]; ok {
			continue
		}
		if _, ok := s["NotResource"]; ok {
			continue
		}
		actions := stringListAny(s["Action"])
		if len(actions) == 0 {
			continue
		}
		resources := stringListAny(s["Resource"])
		if len(resources) == 0 {
			resources = []string{"*"} // Resource omitted defaults to "*"
		}
		lowered := make([]string, 0, len(actions))
		for _, a := range actions {
			a = strings.TrimSpace(a)
			if a != "" {
				lowered = append(lowered, strings.ToLower(a))
			}
		}
		if len(lowered) == 0 {
			continue
		}
		out = append(out, iamAllowStmt{actions: lowered, resources: resources})
	}
	return out
}

// stringList normalizes a JSON string-or-list into a []string.
// Anything else yields nil.
func stringListAny(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// iamActionCovers reports whether a granted action pattern (which may
// contain "*") covers a concrete wanted action. Both are matched
// case-insensitively; wanted must already be lower-cased.
func iamActionCovers(granted, wanted string) bool {
	granted = strings.ToLower(strings.TrimSpace(granted))
	if granted == "" {
		return false
	}
	if !strings.Contains(granted, "*") {
		return granted == wanted
	}
	// Glob match: split on "*" and require ordered segment containment.
	parts := strings.Split(granted, "*")
	pos := 0
	for i, p := range parts {
		if p == "" {
			continue
		}
		if i == 0 && !strings.HasPrefix(granted, "*") {
			if !strings.HasPrefix(wanted[pos:], p) {
				return false
			}
			pos += len(p)
			continue
		}
		idx := strings.Index(wanted[pos:], p)
		if idx < 0 {
			return false
		}
		pos += idx + len(p)
	}
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(granted, "*") {
		return strings.HasSuffix(wanted, last)
	}
	return true
}

// iamGrantsAny reports whether any statement grants (covers) any of the
// wanted concrete actions. Wanted actions must be lower-cased.
func iamGrantsAny(stmts []iamAllowStmt, wanted ...string) bool {
	for _, s := range stmts {
		for _, g := range s.actions {
			for _, w := range wanted {
				if iamActionCovers(g, w) {
					return true
				}
			}
		}
	}
	return false
}

// iamGrantsOnStar reports whether any statement grants (covers) any of the
// wanted actions on Resource "*".
func iamGrantsOnStar(stmts []iamAllowStmt, wanted ...string) bool {
	for _, s := range stmts {
		onStar := false
		for _, r := range s.resources {
			if strings.TrimSpace(r) == "*" {
				onStar = true
				break
			}
		}
		if !onStar {
			continue
		}
		for _, g := range s.actions {
			for _, w := range wanted {
				if iamActionCovers(g, w) {
					return true
				}
			}
		}
	}
	return false
}

// iamPrivilegeAppliesTo is the shared AppliesTo for the Tier 1 rules.
func iamPrivilegeAppliesTo(resType string) bool {
	return resType == "aws_iam_policy" ||
		resType == "aws_iam_role_policy" ||
		resType == "aws_iam_user_policy"
}

// iamPolicyStmts fetches and parses the policy document for a resource.
// Returns nil when absent, unknown, or unparseable.
func iamPolicyStmts(r ir.Resource) ([]iamAllowStmt, ir.Span, bool) {
	pol, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil, ir.Span{}, false
	}
	stmts := parseIAMAllowStatements(pol)
	if len(stmts) == 0 {
		return nil, ir.Span{}, false
	}
	return stmts, span, true
}

func iamPrivilegeFinding(rule ir.Rule, r ir.Resource, span ir.Span, actual, expected string) ir.Finding {
	return ir.Finding{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "policy",
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-501 (CKV_AWS_286): IAM privilege escalation via policy
// authoring + attachment primitives.
// ---------------------------------------------------------------------------

type iamPrivilegeEscalation struct{}

func (iamPrivilegeEscalation) ID() string { return "AEGIS-AWS-501" }
func (iamPrivilegeEscalation) Title() string {
	return "IAM policy allows privilege escalation (create policy + attach policy)"
}
func (iamPrivilegeEscalation) Description() string {
	return "The policy combines a policy-authoring action (iam:CreatePolicy, " +
		"iam:PutRolePolicy, iam:PutUserPolicy, iam:PutGroupPolicy) with a " +
		"policy-attachment action (iam:AttachRolePolicy, iam:AttachUserPolicy, " +
		"iam:AttachGroupPolicy). Attack path: create an administrative " +
		"policy, attach it to your own role/user, assume full admin. " +
		"Split authoring from attachment duties and scope each to least privilege."
}
func (iamPrivilegeEscalation) Severity() ir.Severity { return ir.SeverityCritical }
func (iamPrivilegeEscalation) AppliesTo(resType string) bool {
	return iamPrivilegeAppliesTo(resType)
}

var iam501Authoring = []string{
	"iam:createpolicy",
	"iam:putrolepolicy",
	"iam:putuserpolicy",
	"iam:putgrouppolicy",
	"iam:createpolicyversion",
}

var iam501Attachment = []string{
	"iam:attachrolepolicy",
	"iam:attachuserpolicy",
	"iam:attachgrouppolicy",
}

func (r iamPrivilegeEscalation) Check(res ir.Resource) []ir.Finding {
	stmts, span, ok := iamPolicyStmts(res)
	if !ok {
		return nil
	}
	if iamGrantsAny(stmts, iam501Authoring...) && iamGrantsAny(stmts, iam501Attachment...) {
		return []ir.Finding{iamPrivilegeFinding(r, res, span,
			"Allow statements grant policy-authoring and policy-attachment actions",
			"separate policy authoring from attachment; scope both to least privilege")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-502 (CKV_AWS_287): credential exposure via iam:PassRole on "*"
// combined with a role-assumption primitive.
// ---------------------------------------------------------------------------

type iamPassRoleEscalation struct{}

func (iamPassRoleEscalation) ID() string { return "AEGIS-AWS-502" }
func (iamPassRoleEscalation) Title() string {
	return "IAM policy allows privilege escalation via iam:PassRole on * with compute launch"
}
func (iamPassRoleEscalation) Description() string {
	return "The policy allows iam:PassRole on \"*\" together with a " +
		"role-assumption primitive (ec2:RunInstances, lambda:CreateFunction, " +
		"lambda:UpdateFunctionCode, ...). Attack path: launch a compute " +
		"resource passing an administrative role, then steal its credentials " +
		"from the instance metadata / environment. Scope iam:PassRole to " +
		"specific role ARNs."
}
func (iamPassRoleEscalation) Severity() ir.Severity { return ir.SeverityCritical }
func (iamPassRoleEscalation) AppliesTo(resType string) bool {
	return iamPrivilegeAppliesTo(resType)
}

// iam502Primitives are actions that let an attacker execute code under a
// passed role's credentials.
var iam502Primitives = []string{
	"ec2:runinstances",
	"lambda:createfunction",
	"lambda:updatefunctioncode",
	"lambda:updatefunctionconfiguration",
	"glue:createdevendpoint",
	"glue:updatedevendpoint",
	"sagemaker:createtrainingjob",
	"sagemaker:createnotebookinstance",
	"cloudformation:createstack",
	"cloudformation:updatestack",
	"datapipeline:createpipeline",
	"ecs:runtask",
	"batch:submitjob",
}

func (r iamPassRoleEscalation) Check(res ir.Resource) []ir.Finding {
	stmts, span, ok := iamPolicyStmts(res)
	if !ok {
		return nil
	}
	if iamGrantsOnStar(stmts, "iam:passrole") && iamGrantsAny(stmts, iam502Primitives...) {
		return []ir.Finding{iamPrivilegeFinding(r, res, span,
			"Allow statements grant iam:PassRole on \"*\" with a compute-launch primitive",
			"scope iam:PassRole to specific role ARNs")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-503 (CKV_AWS_288): data exfiltration primitives.
// ---------------------------------------------------------------------------

type iamDataExfiltration struct{}

func (iamDataExfiltration) ID() string { return "AEGIS-AWS-503" }
func (iamDataExfiltration) Title() string {
	return "IAM policy allows data exfiltration primitives"
}
func (iamDataExfiltration) Description() string {
	return "The policy grants a known exfiltration pair: s3:GetObject + " +
		"s3:PutObject on \"*\" (copy data to an attacker bucket), " +
		"rds:CreateDBSnapshot + rds:ModifyDBSnapshotAttribute (share a " +
		"snapshot cross-account), or ec2:CreateSnapshot + " +
		"ec2:ModifySnapshotAttribute (share an EBS snapshot). Attack path: " +
		"snapshot or copy production data, share it outside the account. " +
		"Scope data-plane actions to specific resources."
}
func (iamDataExfiltration) Severity() ir.Severity { return ir.SeverityHigh }
func (iamDataExfiltration) AppliesTo(resType string) bool {
	return iamPrivilegeAppliesTo(resType)
}

// iam503Pairs are action pairs whose combination enables exfiltration.
// Each pair is (actions, requireStar): when requireStar is true both
// actions must be granted on "*".
var iam503Pairs = []struct {
	actions     []string
	requireStar bool
	label       string
}{
	{[]string{"s3:getobject", "s3:putobject"}, true, "s3:GetObject + s3:PutObject on \"*\""},
	{[]string{"rds:createdbsnapshot", "rds:modifydbsnapshotattribute"}, false, "rds:CreateDBSnapshot + rds:ModifyDBSnapshotAttribute"},
	{[]string{"ec2:createsnapshot", "ec2:modifysnapshotattribute"}, false, "ec2:CreateSnapshot + ec2:ModifySnapshotAttribute"},
}

func (r iamDataExfiltration) Check(res ir.Resource) []ir.Finding {
	stmts, span, ok := iamPolicyStmts(res)
	if !ok {
		return nil
	}
	for _, pair := range iam503Pairs {
		all := true
		for _, a := range pair.actions {
			var granted bool
			if pair.requireStar {
				granted = iamGrantsOnStar(stmts, a)
			} else {
				granted = iamGrantsAny(stmts, a)
			}
			if !granted {
				all = false
				break
			}
		}
		if all {
			return []ir.Finding{iamPrivilegeFinding(r, res, span,
				"Allow statements grant exfiltration pair "+pair.label,
				"scope data-plane actions to specific resources")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-504 (CKV_AWS_289): permissions management without constraints.
// ---------------------------------------------------------------------------

type iamPermissionsMgmt struct{}

func (iamPermissionsMgmt) ID() string { return "AEGIS-AWS-504" }
func (iamPermissionsMgmt) Title() string {
	return "IAM permissions management actions allowed on all resources"
}
func (iamPermissionsMgmt) Description() string {
	return "An Allow statement grants IAM write actions (iam:Put*, " +
		"iam:Create*, iam:Update*, iam:Delete*, iam:Attach*, iam:Detach*, or " +
		"iam:*) on Resource \"*\". Attack path: modify any identity's " +
		"policies directly to escalate to admin. Read-only IAM actions " +
		"(iam:Get*, iam:List*, iam:Generate*, iam:Simulate*) are excluded. " +
		"Scope IAM management to specific users, roles, and policies."
}
func (iamPermissionsMgmt) Severity() ir.Severity { return ir.SeverityHigh }
func (iamPermissionsMgmt) AppliesTo(resType string) bool {
	return iamPrivilegeAppliesTo(resType)
}

// iam504WritePrefixes are lower-cased action-name prefixes (after "iam:")
// that constitute permissions management. "iam:*" itself always matches.
var iam504WritePrefixes = []string{
	"put", "create", "update", "delete", "attach", "detach",
	"add", "remove", "set", "enable", "disable", "tag", "untag",
	"change", "deactivate", "upload", "sync",
}

// iam504ReadPrefixes are excluded from 504 (observability, not management).
var iam504ReadPrefixes = []string{
	"get", "list", "generate", "simulate",
}

func iamIsPermissionsMgmt(action string) bool {
	// action is lower-cased already.
	if action == "*" || action == "iam:*" {
		return true
	}
	if !strings.HasPrefix(action, "iam:") {
		return false
	}
	name := strings.TrimPrefix(action, "iam:")
	// Wildcard suffix: match the literal prefix before "*".
	if idx := strings.Index(name, "*"); idx >= 0 {
		name = name[:idx]
	}
	for _, rp := range iam504ReadPrefixes {
		if strings.HasPrefix(name, rp) {
			return false
		}
	}
	for _, wp := range iam504WritePrefixes {
		if strings.HasPrefix(name, wp) {
			return true
		}
	}
	return false
}

func (r iamPermissionsMgmt) Check(res ir.Resource) []ir.Finding {
	stmts, span, ok := iamPolicyStmts(res)
	if !ok {
		return nil
	}
	for _, s := range stmts {
		onStar := false
		for _, rs := range s.resources {
			if strings.TrimSpace(rs) == "*" {
				onStar = true
				break
			}
		}
		if !onStar {
			continue
		}
		for _, a := range s.actions {
			if iamIsPermissionsMgmt(a) {
				return []ir.Finding{iamPrivilegeFinding(r, res, span,
					"Allow statement grants IAM management action \""+a+"\" on \"*\"",
					"scope IAM management actions to specific identities")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-505 (CKV_AWS_290): write access without resource constraints.
// ---------------------------------------------------------------------------

type iamWriteNoConstraints struct{}

func (iamWriteNoConstraints) ID() string { return "AEGIS-AWS-505" }
func (iamWriteNoConstraints) Title() string {
	return "Write actions allowed on all resources"
}
func (iamWriteNoConstraints) Description() string {
	return "An Allow statement grants write actions (*:Put*, *:Create*, " +
		"*:Update*, *:Delete*, *:Modify*) on Resource \"*\". Attack path: " +
		"unconstrained writes let an attacker reconfigure, exfiltrate from, " +
		"or destroy any resource in the account. The blanket Action \"*\" " +
		"case is owned by AEGIS-AWS-006. Scope write actions to the " +
		"resources the workload actually manages."
}
func (iamWriteNoConstraints) Severity() ir.Severity { return ir.SeverityHigh }
func (iamWriteNoConstraints) AppliesTo(resType string) bool {
	return iamPrivilegeAppliesTo(resType)
}

// iam505WriteVerbs are lower-cased action-name verbs (after "service:")
// that count as writes for rule 505.
var iam505WriteVerbs = []string{
	"put", "create", "update", "delete", "modify",
	"attach", "detach", "run", "start", "stop", "terminate",
}

func iamIsUnconstrainedWrite(action string) bool {
	// action is lower-cased already. Blanket "*" is AEGIS-AWS-006's case.
	if action == "*" {
		return false
	}
	colon := strings.Index(action, ":")
	if colon < 0 {
		return false
	}
	name := action[colon+1:]
	// Service-level wildcard (e.g. "s3:*") includes every write verb.
	if name == "*" {
		return true
	}
	if idx := strings.Index(name, "*"); idx >= 0 {
		name = name[:idx]
	}
	for _, v := range iam505WriteVerbs {
		if strings.HasPrefix(name, v) {
			return true
		}
	}
	return false
}

func (r iamWriteNoConstraints) Check(res ir.Resource) []ir.Finding {
	stmts, span, ok := iamPolicyStmts(res)
	if !ok {
		return nil
	}
	for _, s := range stmts {
		onStar := false
		for _, rs := range s.resources {
			if strings.TrimSpace(rs) == "*" {
				onStar = true
				break
			}
		}
		if !onStar {
			continue
		}
		for _, a := range s.actions {
			if iamIsUnconstrainedWrite(a) {
				return []ir.Finding{iamPrivilegeFinding(r, res, span,
					"Allow statement grants write action \""+a+"\" on \"*\"",
					"scope write actions to specific resources")}
			}
		}
	}
	return nil
}

// IAMPrivilegeRules returns the Tier 1 IAM privilege escalation rules
// (AEGIS-AWS-501..505) in ID order.
func IAMPrivilegeRules() []ir.Rule {
	return []ir.Rule{
		iamPrivilegeEscalation{}, // AEGIS-AWS-501
		iamPassRoleEscalation{},  // AEGIS-AWS-502
		iamDataExfiltration{},    // AEGIS-AWS-503
		iamPermissionsMgmt{},     // AEGIS-AWS-504
		iamWriteNoConstraints{},  // AEGIS-AWS-505
	}
}
