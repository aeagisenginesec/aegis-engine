package aws

import (
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
// statements (see iam_policy_eval.go). NotAction/NotResource are evaluated
// with real policy-evaluation semantics: a NotAction statement grants
// every action its exclusion list does not cover, and a NotResource
// statement grants on every resource its exclusion list does not cover.
// Unparseable documents and unknown values still yield no findings
// (cannot decide -> silent).
// ---------------------------------------------------------------------------

// iamAllowStmt is one normalized Allow statement. Actions are lower-cased
// for matching (IAM actions are case-insensitive); see
// iamNormalizedStmt in iam_policy_eval.go for the evaluation semantics.
type iamAllowStmt struct {
	n *iamNormalizedStmt
}

// parseIAMAllowStatements extracts Allow statements from a policy JSON
// document. Returns nil when the document cannot be parsed or has no
// usable Allow statements. Statements using NotAction/NotResource are
// evaluated with policy-evaluation semantics, not skipped.
func parseIAMAllowStatements(doc string) []iamAllowStmt {
	var out []iamAllowStmt
	for _, s := range policyStatements(doc) {
		n := normalizeIAMStmt(s)
		// No action element: nothing is granted by this statement.
		if n == nil || (!n.hasAction && !n.hasNotAction) {
			continue
		}
		out = append(out, iamAllowStmt{n: n})
	}
	return out
}

// iamGrantsAny reports whether any statement grants (covers) any of the
// wanted concrete actions. Wanted actions must be lower-cased. A
// NotAction statement grants a wanted action unless its exclusion list
// covers it.
func iamGrantsAny(stmts []iamAllowStmt, wanted ...string) bool {
	for _, s := range stmts {
		for _, w := range wanted {
			if s.n.grantsAction(w) {
				return true
			}
		}
	}
	return false
}

// iamGrantsOnClass reports whether any statement grants any of the wanted
// actions on the whole resource class described by classGlob (e.g.
// iamRoleARNClass for iam:PassRole, iamS3BucketARNClass for the S3
// exfiltration pair). A NotResource statement grants on the class unless
// an exclusion pattern covers the class — so excluding every role ARN
// silences 502, while excluding one bucket does not silence 503.
func iamGrantsOnClass(stmts []iamAllowStmt, classGlob string, wanted ...string) bool {
	for _, s := range stmts {
		if !s.n.grantsOnClass(classGlob) {
			continue
		}
		for _, w := range wanted {
			if s.n.grantsAction(w) {
				return true
			}
		}
	}
	return false
}

// iamGrantNotes collects the exclusion notes of the statements granting
// any of the wanted actions, so a finding's evidence names the scope the
// policy explicitly excludes instead of claiming it.
func iamGrantNotes(stmts []iamAllowStmt, wanted ...string) string {
	var notes []string
	seen := map[string]bool{}
	for _, s := range stmts {
		grants := false
		for _, w := range wanted {
			if s.n.grantsAction(w) {
				grants = true
				break
			}
		}
		if !grants {
			continue
		}
		if note := s.n.exclusionNote(); note != "" && !seen[note] {
			seen[note] = true
			notes = append(notes, note)
		}
	}
	return strings.Join(notes, "; ")
}

// iamGrantNotesOnClass is iamGrantNotes restricted to statements granting
// on the given resource class.
func iamGrantNotesOnClass(stmts []iamAllowStmt, classGlob string, wanted ...string) string {
	var notes []string
	seen := map[string]bool{}
	for _, s := range stmts {
		if !s.n.grantsOnClass(classGlob) {
			continue
		}
		grants := false
		for _, w := range wanted {
			if s.n.grantsAction(w) {
				grants = true
				break
			}
		}
		if !grants {
			continue
		}
		if note := s.n.exclusionNote(); note != "" && !seen[note] {
			seen[note] = true
			notes = append(notes, note)
		}
	}
	return strings.Join(notes, "; ")
}

// iam504Witnesses are representative IAM permissions-management actions.
// A NotAction statement grants a management action unless its exclusion
// list covers every witness family — i.e. unless it genuinely grants no
// IAM write action. Positive statements are checked pattern-by-pattern
// with iamIsPermissionsMgmt instead (see findMgmtGrant).
var iam504Witnesses = []string{
	"iam:putuserpolicy",
	"iam:createpolicy",
	"iam:deleteuser",
	"iam:attachrolepolicy",
	"iam:updateuser",
}

// findMgmtGrant reports whether the statement grants an IAM permissions
// management action on "*", returning the matched action (the granted
// pattern for positive statements, the first granted witness action for
// NotAction statements) and the statement's exclusion note.
// Positive statements are tested pattern-by-pattern; NotAction
// statements are tested against representative witness actions.
func (s iamAllowStmt) findMgmtGrant() (string, string) {
	if !s.n.grantsOnStar() {
		return "", ""
	}
	if s.n.hasAction {
		for _, a := range s.n.actions {
			if iamIsPermissionsMgmt(a) {
				return a, s.n.exclusionNote()
			}
		}
		return "", ""
	}
	if s.n.hasNotAction {
		for _, w := range iam504Witnesses {
			if s.n.grantsAction(w) {
				return w, s.n.exclusionNote()
			}
		}
	}
	return "", ""
}

// iam505Witnesses are representative unconstrained write actions across
// services, used the same way as iam504Witnesses for NotAction
// statements.
var iam505Witnesses = []string{
	"s3:putobject",
	"ec2:terminateinstances",
	"rds:deletedbinstance",
	"lambda:updatefunctioncode",
	"dynamodb:deleteitem",
}

// findWriteGrant reports whether the statement grants an unconstrained
// write action on "*", returning the matched action and the statement's
// exclusion note (see findMgmtGrant).
func (s iamAllowStmt) findWriteGrant() (string, string) {
	if !s.n.grantsOnStar() {
		return "", ""
	}
	if s.n.hasAction {
		for _, a := range s.n.actions {
			if iamIsUnconstrainedWrite(a) {
				return a, s.n.exclusionNote()
			}
		}
		return "", ""
	}
	if s.n.hasNotAction {
		for _, w := range iam505Witnesses {
			if s.n.grantsAction(w) {
				return w, s.n.exclusionNote()
			}
		}
	}
	return "", ""
}

// withNote appends a parenthesized exclusion note to a finding's Actual
// evidence string when the grant came via NotAction/NotResource.
func withNote(actual, note string) string {
	if note == "" {
		return actual
	}
	return actual + " (" + note + ")"
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
		both := append(append([]string{}, iam501Authoring...), iam501Attachment...)
		return []ir.Finding{iamPrivilegeFinding(r, res, span,
			withNote("Allow statements grant policy-authoring and policy-attachment actions",
				iamGrantNotes(stmts, both...)),
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
	if iamGrantsOnClass(stmts, iamRoleARNClass, "iam:passrole") && iamGrantsAny(stmts, iam502Primitives...) {
		note := iamGrantNotesOnClass(stmts, iamRoleARNClass, "iam:passrole")
		if prim := iamGrantNotes(stmts, iam502Primitives...); prim != "" {
			if note != "" {
				note += "; " + prim
			} else {
				note = prim
			}
		}
		return []ir.Finding{iamPrivilegeFinding(r, res, span,
			withNote("Allow statements grant iam:PassRole on \"*\" with a compute-launch primitive", note),
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
		var note string
		for _, a := range pair.actions {
			var granted bool
			if pair.requireStar {
				// S3 data-plane actions act on buckets: the grant must
				// cover the bucket class, so a NotResource that excludes
				// every bucket silences the pair.
				granted = iamGrantsOnClass(stmts, iamS3BucketARNClass, a)
			} else {
				granted = iamGrantsAny(stmts, a)
			}
			if !granted {
				all = false
				break
			}
		}
		if all {
			if pair.requireStar {
				note = iamGrantNotesOnClass(stmts, iamS3BucketARNClass, pair.actions...)
			} else {
				note = iamGrantNotes(stmts, pair.actions...)
			}
			return []ir.Finding{iamPrivilegeFinding(r, res, span,
				withNote("Allow statements grant exfiltration pair "+pair.label, note),
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
		if a, note := s.findMgmtGrant(); a != "" {
			return []ir.Finding{iamPrivilegeFinding(r, res, span,
				withNote("Allow statement grants IAM management action \""+a+"\" on \"*\"", note),
				"scope IAM management actions to specific identities")}
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
		if a, note := s.findWriteGrant(); a != "" {
			return []ir.Finding{iamPrivilegeFinding(r, res, span,
				withNote("Allow statement grants write action \""+a+"\" on \"*\"", note),
				"scope write actions to specific resources")}
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
