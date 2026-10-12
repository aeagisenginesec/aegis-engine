// Package aws implements the Aegis AWS security rule pack.
//
// IAM deep rules (AEGIS-AWS-650..679): granular IAM hygiene and privilege
// checks. Unknown-value contract (hard rule): a present-but-unresolved
// attribute yields NO finding. An ABSENT attribute fires only when the
// provider default is insecure, via absentInsecureDefault.
package aws

import (
	"sort"
	"strconv"
	"strings"

	"aegis/internal/ir"
)

// IAMDeepRules returns rules 650-679.
func IAMDeepRules() []ir.Rule {
	return []ir.Rule{
		iamPasswordMinLength{},       // AEGIS-AWS-650
		iamPasswordNoUppercase{},     // AEGIS-AWS-651
		iamPasswordNoLowercase{},     // AEGIS-AWS-652
		iamPasswordNoNumbers{},       // AEGIS-AWS-653
		iamPasswordNoSymbols{},       // AEGIS-AWS-654
		iamPasswordReuseAllowed{},    // AEGIS-AWS-655
		iamPasswordMaxAgeWeak{},      // AEGIS-AWS-656
		iamGroupInlinePolicy{},       // AEGIS-AWS-657
		iamRoleInlinePolicy{},        // AEGIS-AWS-658
		iamUserInlinePolicy{},        // AEGIS-AWS-659
		iamPolicySensitiveWildcard{}, // AEGIS-AWS-660
		iamPolicyPassRoleStar{},      // AEGIS-AWS-661
		iamAccountAliasMissing{},     // AEGIS-AWS-662
		iamPasswordExpiryAbsent{},    // AEGIS-AWS-663
		iamUserForceDestroy{},        // AEGIS-AWS-664
		iamRoleForceDetach{},         // AEGIS-AWS-665
		iamAttachmentAdminAccess{},   // AEGIS-AWS-666
		iamRoleNoBoundary{},          // AEGIS-AWS-667
		iamAccessKeyUnencrypted{},    // AEGIS-AWS-668
		iamAttachmentPowerUser{},     // AEGIS-AWS-669
		iamPolicyIamStarScoped{},     // AEGIS-AWS-670
		iamPolicyNotResourceAllow{},  // AEGIS-AWS-671
		iamUserUntagged{},            // AEGIS-AWS-672
		iamRoleNoDescription{},       // AEGIS-AWS-673
		iamGroupNamedAdmin{},         // AEGIS-AWS-674
		iamPasswordHardExpiryOff{},   // AEGIS-AWS-675
		iamRoleTagSessionOpen{},      // AEGIS-AWS-676
		iamPolicyStatementNoSid{},    // AEGIS-AWS-677
		iamLoginProfileNoReset{},     // AEGIS-AWS-678
		iamRoleReadOnlyProd{},        // AEGIS-AWS-679
	}
}

// iamDeepFinding builds a standard finding for these rules.
func iamDeepFinding(rule ir.Rule, r ir.Resource, attr string, span ir.Span, actual, expected string) []ir.Finding {
	return []ir.Finding{{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}}
}

// iamDeepPasswordFlag fires when a require_* password boolean is absent
// (provider default false = not required) or explicitly false.
func iamDeepPasswordFlag(rule ir.Rule, r ir.Resource, attr string) []ir.Finding {
	v, span, present, known := getBool(r, attr)
	if !present {
		return absentInsecureDefault(rule, r, attr,
			"absent (AWS default: not required)", "true")
	}
	if !known || v {
		return nil
	}
	return iamDeepFinding(rule, r, attr, span, "false", "true")
}

// iamDeepStmtStrings normalizes an Action/Resource-style statement field
// (string or list of strings) to a string slice. Anything else yields nil.
func iamDeepStmtStrings(v any) []string {
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

// iamDeepActionIs reports whether any action equals one of the targets
// (case-insensitive, trimmed).
func iamDeepActionIs(actions []string, targets ...string) bool {
	for _, a := range actions {
		a = strings.TrimSpace(a)
		for _, t := range targets {
			if strings.EqualFold(a, t) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-650: IAM password policy minimum length < 14
// ---------------------------------------------------------------------------

type iamPasswordMinLength struct{}

func (iamPasswordMinLength) ID() string { return "AEGIS-AWS-650" }
func (iamPasswordMinLength) Title() string {
	return "IAM password policy minimum length below 14"
}
func (iamPasswordMinLength) Description() string {
	return "The account password policy allows passwords shorter than 14 " +
		"characters. Short minimum lengths make console passwords far easier " +
		"to brute-force. Set minimum_password_length to 14 or more."
}
func (iamPasswordMinLength) Severity() ir.Severity { return ir.SeverityHigh }
func (iamPasswordMinLength) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}
func (r iamPasswordMinLength) Check(res ir.Resource) []ir.Finding {
	n, span, present, known := getNumber(res, "minimum_password_length")
	if !present {
		return absentInsecureDefault(r, res, "minimum_password_length",
			"absent (AWS default: no custom minimum enforced)", ">= 14")
	}
	if !known {
		return nil
	}
	if n < 14 {
		return iamDeepFinding(r, res, "minimum_password_length", span,
			strconv.FormatFloat(n, 'f', -1, 64), ">= 14")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-651: IAM password policy has no uppercase requirement
// ---------------------------------------------------------------------------

type iamPasswordNoUppercase struct{}

func (iamPasswordNoUppercase) ID() string { return "AEGIS-AWS-651" }
func (iamPasswordNoUppercase) Title() string {
	return "IAM password policy does not require uppercase characters"
}
func (iamPasswordNoUppercase) Description() string {
	return "The account password policy does not require uppercase letters, " +
		"shrinking the password search space. Set " +
		"require_uppercase_characters to true."
}
func (iamPasswordNoUppercase) Severity() ir.Severity { return ir.SeverityMedium }
func (iamPasswordNoUppercase) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}
func (r iamPasswordNoUppercase) Check(res ir.Resource) []ir.Finding {
	return iamDeepPasswordFlag(r, res, "require_uppercase_characters")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-652: IAM password policy has no lowercase requirement
// ---------------------------------------------------------------------------

type iamPasswordNoLowercase struct{}

func (iamPasswordNoLowercase) ID() string { return "AEGIS-AWS-652" }
func (iamPasswordNoLowercase) Title() string {
	return "IAM password policy does not require lowercase characters"
}
func (iamPasswordNoLowercase) Description() string {
	return "The account password policy does not require lowercase letters, " +
		"shrinking the password search space. Set " +
		"require_lowercase_characters to true."
}
func (iamPasswordNoLowercase) Severity() ir.Severity { return ir.SeverityMedium }
func (iamPasswordNoLowercase) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}
func (r iamPasswordNoLowercase) Check(res ir.Resource) []ir.Finding {
	return iamDeepPasswordFlag(r, res, "require_lowercase_characters")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-653: IAM password policy has no numbers requirement
// ---------------------------------------------------------------------------

type iamPasswordNoNumbers struct{}

func (iamPasswordNoNumbers) ID() string { return "AEGIS-AWS-653" }
func (iamPasswordNoNumbers) Title() string {
	return "IAM password policy does not require numbers"
}
func (iamPasswordNoNumbers) Description() string {
	return "The account password policy does not require numeric characters, " +
		"shrinking the password search space. Set require_numbers to true."
}
func (iamPasswordNoNumbers) Severity() ir.Severity { return ir.SeverityMedium }
func (iamPasswordNoNumbers) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}
func (r iamPasswordNoNumbers) Check(res ir.Resource) []ir.Finding {
	return iamDeepPasswordFlag(r, res, "require_numbers")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-654: IAM password policy has no symbols requirement
// ---------------------------------------------------------------------------

type iamPasswordNoSymbols struct{}

func (iamPasswordNoSymbols) ID() string { return "AEGIS-AWS-654" }
func (iamPasswordNoSymbols) Title() string {
	return "IAM password policy does not require symbols"
}
func (iamPasswordNoSymbols) Description() string {
	return "The account password policy does not require symbol characters, " +
		"shrinking the password search space. Set require_symbols to true."
}
func (iamPasswordNoSymbols) Severity() ir.Severity { return ir.SeverityMedium }
func (iamPasswordNoSymbols) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}
func (r iamPasswordNoSymbols) Check(res ir.Resource) []ir.Finding {
	return iamDeepPasswordFlag(r, res, "require_symbols")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-655: IAM password policy allows password reuse
// ---------------------------------------------------------------------------

type iamPasswordReuseAllowed struct{}

func (iamPasswordReuseAllowed) ID() string { return "AEGIS-AWS-655" }
func (iamPasswordReuseAllowed) Title() string {
	return "IAM password policy allows password reuse"
}
func (iamPasswordReuseAllowed) Description() string {
	return "The account password policy does not prevent password reuse " +
		"(absent or 0), so users can cycle back to old (possibly compromised) " +
		"passwords. Set password_reuse_prevention to a positive value " +
		"(24 recommended by CIS AWS Foundations Benchmark)."
}
func (iamPasswordReuseAllowed) Severity() ir.Severity { return ir.SeverityMedium }
func (iamPasswordReuseAllowed) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}
func (r iamPasswordReuseAllowed) Check(res ir.Resource) []ir.Finding {
	n, span, present, known := getNumber(res, "password_reuse_prevention")
	if !present {
		return absentInsecureDefault(r, res, "password_reuse_prevention",
			"absent (AWS default: reuse allowed)", "> 0")
	}
	if !known {
		return nil
	}
	// Any explicit positive value is a conscious choice; only absent or 0
	// means reuse is actually allowed.
	if n == 0 {
		return iamDeepFinding(r, res, "password_reuse_prevention", span,
			"0", "> 0")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-656: IAM password maximum age too long or never expires
// ---------------------------------------------------------------------------

type iamPasswordMaxAgeWeak struct{}

func (iamPasswordMaxAgeWeak) ID() string { return "AEGIS-AWS-656" }
func (iamPasswordMaxAgeWeak) Title() string {
	return "IAM password maximum age too long or disabled"
}
func (iamPasswordMaxAgeWeak) Description() string {
	return "The account password policy lets passwords live longer than 90 " +
		"days (or never expire when set to 0), widening the window in which " +
		"a compromised password stays useful. Set max_password_age between " +
		"1 and 90."
}
func (iamPasswordMaxAgeWeak) Severity() ir.Severity { return ir.SeverityMedium }
func (iamPasswordMaxAgeWeak) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}
func (r iamPasswordMaxAgeWeak) Check(res ir.Resource) []ir.Finding {
	n, span, present, known := getNumber(res, "max_password_age")
	if !present || !known {
		return nil // absent is covered by AEGIS-AWS-663; unknown: silent
	}
	if n == 0 {
		return iamDeepFinding(r, res, "max_password_age", span,
			"0 (passwords never expire)", "1-90")
	}
	if n > 90 {
		return iamDeepFinding(r, res, "max_password_age", span,
			strconv.FormatFloat(n, 'f', -1, 64), "<= 90")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-657: IAM group with inline policy
// ---------------------------------------------------------------------------

type iamGroupInlinePolicy struct{}

func (iamGroupInlinePolicy) ID() string    { return "AEGIS-AWS-657" }
func (iamGroupInlinePolicy) Title() string { return "IAM group uses an inline policy" }
func (iamGroupInlinePolicy) Description() string {
	return "The group embeds an inline policy document instead of attaching " +
		"a managed policy. Inline policies cannot be reused, versioned, or " +
		"reviewed centrally. Prefer aws_iam_policy with " +
		"aws_iam_group_policy_attachment."
}
func (iamGroupInlinePolicy) Severity() ir.Severity { return ir.SeverityMedium }
func (iamGroupInlinePolicy) AppliesTo(resType string) bool {
	return resType == "aws_iam_group_policy"
}
func (r iamGroupInlinePolicy) Check(res ir.Resource) []ir.Finding {
	return iamDeepFinding(r, res, "policy", res.Span,
		"inline policy document", "managed policy + attachment")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-658: IAM role with inline policy
// ---------------------------------------------------------------------------

type iamRoleInlinePolicy struct{}

func (iamRoleInlinePolicy) ID() string    { return "AEGIS-AWS-658" }
func (iamRoleInlinePolicy) Title() string { return "IAM role uses an inline policy" }
func (iamRoleInlinePolicy) Description() string {
	return "The role embeds an inline policy document instead of attaching " +
		"a managed policy. Inline policies cannot be reused, versioned, or " +
		"reviewed centrally. Prefer aws_iam_policy with " +
		"aws_iam_role_policy_attachment."
}
func (iamRoleInlinePolicy) Severity() ir.Severity { return ir.SeverityMedium }
func (iamRoleInlinePolicy) AppliesTo(resType string) bool {
	return resType == "aws_iam_role_policy"
}
func (r iamRoleInlinePolicy) Check(res ir.Resource) []ir.Finding {
	return iamDeepFinding(r, res, "policy", res.Span,
		"inline policy document", "managed policy + attachment")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-659: IAM user with inline policy
// ---------------------------------------------------------------------------

type iamUserInlinePolicy struct{}

func (iamUserInlinePolicy) ID() string    { return "AEGIS-AWS-659" }
func (iamUserInlinePolicy) Title() string { return "IAM user uses an inline policy" }
func (iamUserInlinePolicy) Description() string {
	return "The user embeds an inline policy document instead of attaching " +
		"a managed policy. Inline policies cannot be reused, versioned, or " +
		"reviewed centrally. Prefer aws_iam_policy with " +
		"aws_iam_user_policy_attachment."
}
func (iamUserInlinePolicy) Severity() ir.Severity { return ir.SeverityMedium }
func (iamUserInlinePolicy) AppliesTo(resType string) bool {
	return resType == "aws_iam_user_policy"
}
func (r iamUserInlinePolicy) Check(res ir.Resource) []ir.Finding {
	return iamDeepFinding(r, res, "policy", res.Span,
		"inline policy document", "managed policy + attachment")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-660: IAM policy grants sensitive service wildcard on "*"
// ---------------------------------------------------------------------------

type iamPolicySensitiveWildcard struct{}

func (iamPolicySensitiveWildcard) ID() string { return "AEGIS-AWS-660" }
func (iamPolicySensitiveWildcard) Title() string {
	return "IAM policy grants sensitive service wildcard on all resources"
}
func (iamPolicySensitiveWildcard) Description() string {
	return "An Allow statement grants a full-service wildcard (iam:*, " +
		"kms:*, sts:*) on Resource \"*\". These are privilege-escalation " +
		"primitives: iam:* manages identities, kms:* decrypts any key, and " +
		"sts:* assumes roles and federates tokens. Scope both actions and " +
		"resources to least privilege."
}
func (iamPolicySensitiveWildcard) Severity() ir.Severity { return ir.SeverityHigh }
func (iamPolicySensitiveWildcard) AppliesTo(resType string) bool {
	return resType == "aws_iam_policy"
}
func (r iamPolicySensitiveWildcard) Check(res ir.Resource) []ir.Finding {
	pol, span, present, known := getString(res, "policy")
	if !present || !known {
		return nil
	}
	for _, s := range policyStatements(pol) {
		if s["Effect"] != "Allow" {
			continue
		}
		if _, hasNotAction := s["NotAction"]; hasNotAction {
			continue // negative logic: handled by AEGIS-AWS-670
		}
		if !stringOrListHasStar(s["Resource"]) {
			continue
		}
		// AEGIS-AWS-102 already flags Action "*"/"iam:*" on "*"; skip that
		// exact overlap so the same statement is not reported twice.
		if actionIsAdminLike(s["Action"]) {
			continue
		}
		actions := iamDeepStmtStrings(s["Action"])
		var matched []string
		for _, t := range []string{"iam:*", "kms:*", "sts:*"} {
			if iamDeepActionIs(actions, t) {
				matched = append(matched, t)
			}
		}
		if len(matched) == 0 {
			continue
		}
		return iamDeepFinding(r, res, "policy", span,
			"Allow with Action "+strings.Join(matched, ",")+" on Resource \"*\"",
			"scoped Action and Resource lists")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-661: IAM policy grants iam:PassRole on all resources
// ---------------------------------------------------------------------------
//
// NOTE: the originally requested trust-policy check ("role trust allows all
// principals") is already covered by AEGIS-AWS-101 (Critical). This rule
// instead covers the adjacent privilege-escalation primitive
// iam:PassRole on "*", which AEGIS-AWS-502 only flags together with compute
// launch actions.

type iamPolicyPassRoleStar struct{}

func (iamPolicyPassRoleStar) ID() string { return "AEGIS-AWS-661" }
func (iamPolicyPassRoleStar) Title() string {
	return "IAM policy grants iam:PassRole on all resources"
}
func (iamPolicyPassRoleStar) Description() string {
	return "An Allow statement grants iam:PassRole on Resource \"*\". " +
		"PassRole lets the holder hand any role — including privileged ones " +
		"— to an AWS service, a classic privilege-escalation step. Scope " +
		"iam:PassRole to the specific role ARNs the workload needs."
}
func (iamPolicyPassRoleStar) Severity() ir.Severity { return ir.SeverityHigh }
func (iamPolicyPassRoleStar) AppliesTo(resType string) bool {
	return resType == "aws_iam_policy"
}
func (r iamPolicyPassRoleStar) Check(res ir.Resource) []ir.Finding {
	pol, span, present, known := getString(res, "policy")
	if !present || !known {
		return nil
	}
	for _, s := range policyStatements(pol) {
		if s["Effect"] != "Allow" {
			continue
		}
		if _, hasNotAction := s["NotAction"]; hasNotAction {
			continue
		}
		if !iamDeepActionIs(iamDeepStmtStrings(s["Action"]), "iam:PassRole") {
			continue
		}
		if !stringOrListHasStar(s["Resource"]) {
			continue
		}
		return iamDeepFinding(r, res, "policy", span,
			"Allow with Action \"iam:PassRole\" on Resource \"*\"",
			"iam:PassRole scoped to specific role ARNs")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-662: IAM account has no alias
// ---------------------------------------------------------------------------

type iamAccountAliasMissing struct{}

func (iamAccountAliasMissing) ID() string    { return "AEGIS-AWS-662" }
func (iamAccountAliasMissing) Title() string { return "IAM account has no alias" }
func (iamAccountAliasMissing) Description() string {
	return "No aws_iam_account_alias is defined, so the account is only " +
		"identifiable by its numeric ID in the console sign-in URL and in " +
		"audit trails. A memorable alias reduces the risk of operating in " +
		"the wrong account."
}
func (iamAccountAliasMissing) Severity() ir.Severity { return ir.SeverityLow }
func (iamAccountAliasMissing) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}

// Check is a no-op; the cross-resource CheckAll does the work.
func (iamAccountAliasMissing) Check(r ir.Resource) []ir.Finding { return nil }

func (r iamAccountAliasMissing) CheckAll(resources []ir.Resource) []ir.Finding {
	for _, res := range resources {
		if res.Type == "aws_iam_account_alias" {
			return nil
		}
	}
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	for _, res := range sorted {
		if res.Type != "aws_iam_account_password_policy" {
			continue
		}
		if resourceAllUnknown(res) {
			continue // anchor config unresolvable: undecidable
		}
		return iamDeepFinding(r, res, "account_alias", res.Span,
			"absent (AWS default: numeric account ID only)",
			"aws_iam_account_alias defined")
	}
	return nil
}

// resourceAllUnknown reports whether every attribute on the resource is
// unresolved. A fully-unknown anchor cannot support an absence finding.
// An empty attribute map means "known to be empty" and is decidable.
func resourceAllUnknown(res ir.Resource) bool {
	if len(res.Attributes) == 0 {
		return false
	}
	for _, v := range res.Attributes {
		if v.Known {
			return false
		}
	}
	return true
}

var _ ir.CrossResourceRule = iamAccountAliasMissing{}

// ---------------------------------------------------------------------------
// AEGIS-AWS-663: IAM password policy has no maximum age configured
// ---------------------------------------------------------------------------

type iamPasswordExpiryAbsent struct{}

func (iamPasswordExpiryAbsent) ID() string { return "AEGIS-AWS-663" }
func (iamPasswordExpiryAbsent) Title() string {
	return "IAM password policy has no maximum password age"
}
func (iamPasswordExpiryAbsent) Description() string {
	return "The account password policy does not set max_password_age, so " +
		"the AWS default (0, passwords never expire) applies and compromised " +
		"passwords stay valid indefinitely. Set max_password_age between 1 " +
		"and 90."
}
func (iamPasswordExpiryAbsent) Severity() ir.Severity { return ir.SeverityMedium }
func (iamPasswordExpiryAbsent) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}
func (r iamPasswordExpiryAbsent) Check(res ir.Resource) []ir.Finding {
	_, _, present, _ := getNumber(res, "max_password_age")
	if !present {
		return absentInsecureDefault(r, res, "max_password_age",
			"absent (AWS default: 0 - passwords never expire)", "1-90")
	}
	return nil // known values (good or bad) are covered by AEGIS-AWS-656
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-664: IAM user with force_destroy enabled
// ---------------------------------------------------------------------------

type iamUserForceDestroy struct{}

func (iamUserForceDestroy) ID() string { return "AEGIS-AWS-664" }
func (iamUserForceDestroy) Title() string {
	return "IAM user has force_destroy enabled"
}
func (iamUserForceDestroy) Description() string {
	return "force_destroy lets Terraform delete this IAM user even while it " +
		"still has access keys, a login profile, or MFA devices attached, " +
		"destroying credentials without an explicit cleanup step. Keep " +
		"force_destroy false and remove credentials deliberately."
}
func (iamUserForceDestroy) Severity() ir.Severity { return ir.SeverityLow }
func (iamUserForceDestroy) AppliesTo(resType string) bool {
	return resType == "aws_iam_user"
}
func (r iamUserForceDestroy) Check(res ir.Resource) []ir.Finding {
	v, span, present, known := getBool(res, "force_destroy")
	if !present || !known || !v {
		return nil
	}
	return iamDeepFinding(r, res, "force_destroy", span, "true", "false")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-665: IAM role allows forced policy detach on destroy
// ---------------------------------------------------------------------------
//
// NOTE: the originally requested max_session_duration check duplicates
// AEGIS-AWS-554. This rule covers the adjacent destructive-default
// force_detach_policies instead.

type iamRoleForceDetach struct{}

func (iamRoleForceDetach) ID() string { return "AEGIS-AWS-665" }
func (iamRoleForceDetach) Title() string {
	return "IAM role allows forced policy detach on destroy"
}
func (iamRoleForceDetach) Description() string {
	return "force_detach_policies lets Terraform delete this role even while " +
		"policies are still attached, silently dropping guardrails during a " +
		"destroy. Detach policies explicitly instead of relying on the " +
		"forced detach."
}
func (iamRoleForceDetach) Severity() ir.Severity { return ir.SeverityLow }
func (iamRoleForceDetach) AppliesTo(resType string) bool {
	return resType == "aws_iam_role"
}
func (r iamRoleForceDetach) Check(res ir.Resource) []ir.Finding {
	v, span, present, known := getBool(res, "force_detach_policies")
	if !present || !known || !v {
		return nil
	}
	return iamDeepFinding(r, res, "force_detach_policies", span, "true", "false")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-666: policy attachment grants AdministratorAccess
// ---------------------------------------------------------------------------

type iamAttachmentAdminAccess struct{}

func (iamAttachmentAdminAccess) ID() string { return "AEGIS-AWS-666" }
func (iamAttachmentAdminAccess) Title() string {
	return "IAM policy attachment grants AdministratorAccess"
}
func (iamAttachmentAdminAccess) Description() string {
	return "A policy attachment grants the AWS-managed AdministratorAccess " +
		"policy, giving the attached identities full administrative control " +
		"over the account. Replace it with scoped least-privilege policies."
}
func (iamAttachmentAdminAccess) Severity() ir.Severity { return ir.SeverityHigh }
func (iamAttachmentAdminAccess) AppliesTo(resType string) bool {
	// D1 fix: cover every managed-policy attachment vector, not just the
	// standalone aws_iam_policy_attachment resource.
	switch resType {
	case "aws_iam_policy_attachment",
		"aws_iam_role_policy_attachment",
		"aws_iam_user_policy_attachment",
		"aws_iam_group_policy_attachment",
		"aws_iam_role",
		"aws_iam_user",
		"aws_iam_group":
		return true
	}
	return false
}
func (r iamAttachmentAdminAccess) Check(res ir.Resource) []ir.Finding {
	// Attachment resources carry a single policy_arn.
	if arn, span, present, known := getString(res, "policy_arn"); present {
		if !known {
			return nil // unresolved: cannot decide
		}
		if isAdministratorAccessArn(arn) {
			return iamDeepFinding(r, res, "policy_arn", span,
				"attaches AdministratorAccess", "scoped least-privilege policy")
		}
		return nil
	}
	// Roles, users, and groups attach managed policies via managed_policy_arns.
	if v, ok := res.Attributes["managed_policy_arns"]; ok {
		if !v.Known {
			return nil // unresolved: cannot decide
		}
		arns, ok := v.AsList()
		if !ok {
			return nil // unexpected shape: never panic, never flag
		}
		for _, item := range arns {
			s, ok := item.AsString()
			if !ok {
				continue // unknown element: cannot confirm; skip, no FP
			}
			if isAdministratorAccessArn(s) {
				return iamDeepFinding(r, res, "managed_policy_arns", item.Span,
					"attaches AdministratorAccess", "scoped least-privilege policy")
			}
		}
	}
	return nil
}

// isAdministratorAccessArn reports whether a managed-policy ARN is the
// AWS-managed AdministratorAccess policy (name match, case-insensitive).
func isAdministratorAccessArn(arn string) bool {
	return strings.Contains(strings.ToLower(arn), "administratoraccess")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-667: IAM role without permissions boundary
// ---------------------------------------------------------------------------

type iamRoleNoBoundary struct{}

func (iamRoleNoBoundary) ID() string { return "AEGIS-AWS-667" }
func (iamRoleNoBoundary) Title() string {
	return "IAM role has no permissions boundary"
}
func (iamRoleNoBoundary) Description() string {
	return "The role sets no permissions_boundary, so nothing caps the " +
		"maximum permissions its policies can grant — a single overly broad " +
		"policy attachment becomes fully effective. Set a permissions " +
		"boundary as a guardrail."
}
func (iamRoleNoBoundary) Severity() ir.Severity { return ir.SeverityLow }
func (iamRoleNoBoundary) AppliesTo(resType string) bool {
	return resType == "aws_iam_role"
}
func (r iamRoleNoBoundary) Check(res ir.Resource) []ir.Finding {
	_, _, present, known := getString(res, "permissions_boundary")
	if present && known {
		return nil
	}
	if present && !known {
		return nil // unresolved: cannot decide
	}
	return absentInsecureDefault(r, res, "permissions_boundary",
		"absent (AWS default: no boundary)", "permissions_boundary set")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-668: IAM access key created without pgp_key
// ---------------------------------------------------------------------------

type iamAccessKeyUnencrypted struct{}

func (iamAccessKeyUnencrypted) ID() string { return "AEGIS-AWS-668" }
func (iamAccessKeyUnencrypted) Title() string {
	return "IAM access key secret not encrypted with pgp_key"
}
func (iamAccessKeyUnencrypted) Description() string {
	return "An active access key is created without pgp_key, so the secret " +
		"access key is stored in plaintext in the Terraform state. Anyone " +
		"with state access can read the long-lived credential. Set pgp_key " +
		"to encrypt the secret."
}
func (iamAccessKeyUnencrypted) Severity() ir.Severity { return ir.SeverityLow }
func (iamAccessKeyUnencrypted) AppliesTo(resType string) bool {
	return resType == "aws_iam_access_key"
}
func (r iamAccessKeyUnencrypted) Check(res ir.Resource) []ir.Finding {
	status, _, present, known := getString(res, "status")
	// Provider default status is Active when unset.
	active := !present || (known && strings.EqualFold(strings.TrimSpace(status), "Active"))
	if !active {
		return nil
	}
	if _, _, pgpPresent, _ := getString(res, "pgp_key"); pgpPresent {
		return nil // set or unresolved: assume encrypted / undecidable
	}
	return iamDeepFinding(r, res, "pgp_key", res.Span,
		"absent (secret stored in plaintext in state)", "pgp_key set")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-669: policy attachment grants PowerUserAccess
// ---------------------------------------------------------------------------

type iamAttachmentPowerUser struct{}

func (iamAttachmentPowerUser) ID() string { return "AEGIS-AWS-669" }
func (iamAttachmentPowerUser) Title() string {
	return "IAM role policy attachment grants PowerUserAccess"
}
func (iamAttachmentPowerUser) Description() string {
	return "A role policy attachment grants the AWS-managed PowerUserAccess " +
		"policy: full access to every service except IAM user/group " +
		"management. Review whether the role genuinely needs service-wide " +
		"power and scope it down where possible."
}
func (iamAttachmentPowerUser) Severity() ir.Severity { return ir.SeverityMedium }
func (iamAttachmentPowerUser) AppliesTo(resType string) bool {
	return resType == "aws_iam_role_policy_attachment"
}
func (r iamAttachmentPowerUser) Check(res ir.Resource) []ir.Finding {
	arn, span, present, known := getString(res, "policy_arn")
	if !present || !known {
		return nil
	}
	if !strings.Contains(strings.ToLower(arn), "poweruseraccess") {
		return nil
	}
	return iamDeepFinding(r, res, "policy_arn", span,
		"attaches PowerUserAccess", "scoped least-privilege policy")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-670: IAM policy grants iam:* on a scoped resource
// ---------------------------------------------------------------------------
//
// NOTE: the originally requested NotAction+Allow check duplicates
// AEGIS-AWS-553. This rule instead covers the adjacent gap: "iam:*" on a
// specific (non-"*") resource, which AEGIS-AWS-102 does not flag.

type iamPolicyIamStarScoped struct{}

func (iamPolicyIamStarScoped) ID() string { return "AEGIS-AWS-670" }
func (iamPolicyIamStarScoped) Title() string {
	return "IAM policy grants iam:* on a scoped resource"
}
func (iamPolicyIamStarScoped) Description() string {
	return "An Allow statement grants Action \"iam:*\" on specific resource " +
		"ARNs. IAM actions are account-global in effect, so a Resource ARN " +
		"does not meaningfully constrain them, and AEGIS-AWS-102 only " +
		"catches the Resource \"*\" case. Scope the actions to the least " +
		"privilege the workload needs."
}
func (iamPolicyIamStarScoped) Severity() ir.Severity { return ir.SeverityHigh }
func (iamPolicyIamStarScoped) AppliesTo(resType string) bool {
	return resType == "aws_iam_policy"
}
func (r iamPolicyIamStarScoped) Check(res ir.Resource) []ir.Finding {
	pol, span, present, known := getString(res, "policy")
	if !present || !known {
		return nil
	}
	for _, s := range policyStatements(pol) {
		if s["Effect"] != "Allow" {
			continue
		}
		if _, hasNotAction := s["NotAction"]; hasNotAction {
			continue // negative logic: handled by AEGIS-AWS-553
		}
		if !iamDeepActionIs(iamDeepStmtStrings(s["Action"]), "iam:*") {
			continue
		}
		resVal, hasResource := s["Resource"]
		if !hasResource {
			continue // no Resource element: cannot decide
		}
		if stringOrListHasStar(resVal) {
			continue // Resource "*": handled by AEGIS-AWS-102
		}
		return iamDeepFinding(r, res, "policy", span,
			"Allow with Action \"iam:*\" on scoped resources",
			"least-privilege IAM actions")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-671: IAM policy Allow with NotResource
// ---------------------------------------------------------------------------

type iamPolicyNotResourceAllow struct{}

func (iamPolicyNotResourceAllow) ID() string { return "AEGIS-AWS-671" }
func (iamPolicyNotResourceAllow) Title() string {
	return "IAM policy Allow statement uses NotResource"
}
func (iamPolicyNotResourceAllow) Description() string {
	return "An Allow statement uses NotResource, granting the actions on " +
		"every resource except the listed ones. Negative logic is hard to " +
		"audit and silently expands as new resources are created. Rewrite " +
		"with an explicit Resource allowlist."
}
func (iamPolicyNotResourceAllow) Severity() ir.Severity { return ir.SeverityHigh }
func (iamPolicyNotResourceAllow) AppliesTo(resType string) bool {
	return resType == "aws_iam_policy"
}
func (r iamPolicyNotResourceAllow) Check(res ir.Resource) []ir.Finding {
	pol, span, present, known := getString(res, "policy")
	if !present || !known {
		return nil
	}
	for _, s := range policyStatements(pol) {
		if s["Effect"] != "Allow" {
			continue
		}
		if len(iamDeepStmtStrings(s["NotResource"])) == 0 {
			continue
		}
		return iamDeepFinding(r, res, "policy", span,
			"Allow statement with NotResource", "explicit Resource allowlist")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-672: IAM user without tags
// ---------------------------------------------------------------------------

type iamUserUntagged struct{}

func (iamUserUntagged) ID() string    { return "AEGIS-AWS-672" }
func (iamUserUntagged) Title() string { return "IAM user has no tags" }
func (iamUserUntagged) Description() string {
	return "The IAM user carries no tags, making ownership, purpose, and " +
		"lifecycle untraceable in audits and complicating attribute-based " +
		"access control. Tag identities with at least owner and purpose."
}
func (iamUserUntagged) Severity() ir.Severity { return ir.SeverityLow }
func (iamUserUntagged) AppliesTo(resType string) bool {
	return resType == "aws_iam_user"
}
func (r iamUserUntagged) Check(res ir.Resource) []ir.Finding {
	v, ok := res.Attributes["tags"]
	if !ok {
		return absentInsecureDefault(r, res, "tags",
			"absent (AWS default: no tags)", "tags set (owner, purpose)")
	}
	tags, mok := v.AsMap()
	if !mok {
		return nil // unresolved or non-map: silent
	}
	if len(tags) == 0 {
		return iamDeepFinding(r, res, "tags", v.Span, "empty", "at least one tag set")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-673: IAM role without description
// ---------------------------------------------------------------------------

type iamRoleNoDescription struct{}

func (iamRoleNoDescription) ID() string    { return "AEGIS-AWS-673" }
func (iamRoleNoDescription) Title() string { return "IAM role has no description" }
func (iamRoleNoDescription) Description() string {
	return "The IAM role has no description, so reviewers cannot tell what " +
		"the role is for or who owns it. Document the role's purpose in the " +
		"description field."
}
func (iamRoleNoDescription) Severity() ir.Severity { return ir.SeverityLow }
func (iamRoleNoDescription) AppliesTo(resType string) bool {
	return resType == "aws_iam_role"
}
func (r iamRoleNoDescription) Check(res ir.Resource) []ir.Finding {
	d, span, present, known := getString(res, "description")
	if !present {
		return absentInsecureDefault(r, res, "description",
			"absent (AWS default: none)", "description set")
	}
	if !known {
		return nil
	}
	if strings.TrimSpace(d) == "" {
		return iamDeepFinding(r, res, "description", span, "empty", "non-empty description")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-674: IAM group named "admin"
// ---------------------------------------------------------------------------

type iamGroupNamedAdmin struct{}

func (iamGroupNamedAdmin) ID() string { return "AEGIS-AWS-674" }
func (iamGroupNamedAdmin) Title() string {
	return "IAM group named admin should be reviewed"
}
func (iamGroupNamedAdmin) Description() string {
	return "A group literally named \"admin\" conventionally carries " +
		"privileged access. Confirm its membership and attached policies are " +
		"intentional and minimal, or rename it to reflect its actual scope."
}
func (iamGroupNamedAdmin) Severity() ir.Severity { return ir.SeverityMedium }
func (iamGroupNamedAdmin) AppliesTo(resType string) bool {
	return resType == "aws_iam_group"
}
func (r iamGroupNamedAdmin) Check(res ir.Resource) []ir.Finding {
	n, span, present, known := getString(res, "name")
	if !present || !known {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(n), "admin") {
		return nil
	}
	return iamDeepFinding(r, res, "name", span,
		"group named \""+strings.TrimSpace(n)+"\"", "reviewed membership and policies")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-675: IAM password policy hard_expiry disabled
// ---------------------------------------------------------------------------

type iamPasswordHardExpiryOff struct{}

func (iamPasswordHardExpiryOff) ID() string { return "AEGIS-AWS-675" }
func (iamPasswordHardExpiryOff) Title() string {
	return "IAM password policy allows reset after expiry"
}
func (iamPasswordHardExpiryOff) Description() string {
	return "hard_expiry is disabled, so users can set a new password after " +
		"their password has expired instead of being forced through the " +
		"administrative reset flow. Enable hard_expiry for stricter " +
		"expired-password handling."
}
func (iamPasswordHardExpiryOff) Severity() ir.Severity { return ir.SeverityLow }
func (iamPasswordHardExpiryOff) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}
func (r iamPasswordHardExpiryOff) Check(res ir.Resource) []ir.Finding {
	v, span, present, known := getBool(res, "hard_expiry")
	if !present {
		return absentInsecureDefault(r, res, "hard_expiry",
			"absent (AWS default: false)", "true")
	}
	if !known || v {
		return nil
	}
	return iamDeepFinding(r, res, "hard_expiry", span, "false", "true")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-676: IAM role trust grants sts:TagSession without conditions
// ---------------------------------------------------------------------------

type iamRoleTagSessionOpen struct{}

func (iamRoleTagSessionOpen) ID() string { return "AEGIS-AWS-676" }
func (iamRoleTagSessionOpen) Title() string {
	return "IAM role trust grants sts:TagSession without conditions"
}
func (iamRoleTagSessionOpen) Description() string {
	return "A trust-policy Allow statement grants sts:TagSession with no " +
		"Condition, letting callers attach arbitrary session tags when " +
		"assuming the role. Where session tags drive attribute-based access " +
		"decisions, this can widen access. Constrain it with aws:RequestTag " +
		"or aws:TagKeys conditions."
}
func (iamRoleTagSessionOpen) Severity() ir.Severity { return ir.SeverityLow }
func (iamRoleTagSessionOpen) AppliesTo(resType string) bool {
	return resType == "aws_iam_role"
}
func (r iamRoleTagSessionOpen) Check(res ir.Resource) []ir.Finding {
	pol, span, present, known := getString(res, "assume_role_policy")
	if !present || !known {
		return nil
	}
	for _, s := range policyStatements(pol) {
		if s["Effect"] != "Allow" {
			continue
		}
		if _, hasCond := s["Condition"]; hasCond {
			continue // conditioned: cannot prove it is open
		}
		if !iamDeepActionIs(iamDeepStmtStrings(s["Action"]), "sts:TagSession") {
			continue
		}
		return iamDeepFinding(r, res, "assume_role_policy", span,
			"Allow grants sts:TagSession with no Condition",
			"Condition on aws:RequestTag / aws:TagKeys")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-677: IAM policy statement without Sid
// ---------------------------------------------------------------------------

type iamPolicyStatementNoSid struct{}

func (iamPolicyStatementNoSid) ID() string { return "AEGIS-AWS-677" }
func (iamPolicyStatementNoSid) Title() string {
	return "IAM policy statement has no Sid"
}
func (iamPolicyStatementNoSid) Description() string {
	return "At least one policy statement has no Sid, making the statement " +
		"harder to reference in reviews, audit findings, and exception " +
		"tracking. Give every statement a descriptive Sid."
}
func (iamPolicyStatementNoSid) Severity() ir.Severity { return ir.SeverityLow }
func (iamPolicyStatementNoSid) AppliesTo(resType string) bool {
	return resType == "aws_iam_policy"
}
func (r iamPolicyStatementNoSid) Check(res ir.Resource) []ir.Finding {
	pol, span, present, known := getString(res, "policy")
	if !present || !known {
		return nil
	}
	stmts := policyStatements(pol)
	if stmts == nil {
		return nil // unparseable: cannot decide
	}
	for _, s := range stmts {
		sid, _ := s["Sid"].(string)
		if strings.TrimSpace(sid) == "" {
			return iamDeepFinding(r, res, "policy", span,
				"statement without Sid", "Sid set on every statement")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-678: IAM login profile without forced password reset
// ---------------------------------------------------------------------------

type iamLoginProfileNoReset struct{}

func (iamLoginProfileNoReset) ID() string { return "AEGIS-AWS-678" }
func (iamLoginProfileNoReset) Title() string {
	return "IAM login profile does not force password reset"
}
func (iamLoginProfileNoReset) Description() string {
	return "The login profile does not require a password reset on next " +
		"sign-in, so the user keeps working with the initial password that " +
		"was provisioned (and possibly shared). Set " +
		"password_reset_required to true."
}
func (iamLoginProfileNoReset) Severity() ir.Severity { return ir.SeverityMedium }
func (iamLoginProfileNoReset) AppliesTo(resType string) bool {
	return resType == "aws_iam_user_login_profile"
}
func (r iamLoginProfileNoReset) Check(res ir.Resource) []ir.Finding {
	v, span, present, known := getBool(res, "password_reset_required")
	if !present {
		return absentInsecureDefault(r, res, "password_reset_required",
			"absent (AWS default: false)", "true")
	}
	if !known || v {
		return nil
	}
	return iamDeepFinding(r, res, "password_reset_required", span, "false", "true")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-679: prod-like IAM role with broad ReadOnlyAccess
// ---------------------------------------------------------------------------

type iamRoleReadOnlyProd struct{}

func (iamRoleReadOnlyProd) ID() string { return "AEGIS-AWS-679" }
func (iamRoleReadOnlyProd) Title() string {
	return "Production-like IAM role attached to ReadOnlyAccess"
}
func (iamRoleReadOnlyProd) Description() string {
	return "A role whose name suggests a production workload attaches the " +
		"AWS-managed ReadOnlyAccess policy: read access to every resource in " +
		"the account. Production roles should use scoped read policies " +
		"limited to the resources they operate on."
}
func (iamRoleReadOnlyProd) Severity() ir.Severity { return ir.SeverityLow }
func (iamRoleReadOnlyProd) AppliesTo(resType string) bool {
	return resType == "aws_iam_role"
}
func (r iamRoleReadOnlyProd) Check(res ir.Resource) []ir.Finding {
	name, _, namePresent, nameKnown := getString(res, "name")
	effective := res.Name
	if namePresent && nameKnown {
		effective = name
	}
	if !strings.Contains(strings.ToLower(effective), "prod") {
		return nil
	}
	v, ok := res.Attributes["managed_policy_arns"]
	if !ok || !v.Known {
		return nil
	}
	list, lok := v.AsList()
	if !lok {
		return nil
	}
	arnSpan := v.Span
	for _, item := range list {
		s, sok := item.AsString()
		if !sok {
			return nil // unresolved element: cannot decide
		}
		if strings.Contains(strings.ToLower(s), "readonlyaccess") {
			return iamDeepFinding(r, res, "managed_policy_arns", arnSpan,
				"ReadOnlyAccess attached to prod-like role \""+strings.TrimSpace(effective)+"\"",
				"scoped read-only policy")
		}
	}
	return nil
}
