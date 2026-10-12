package aws

import (
	"strings"

	"aegis/internal/ir"
)

// IdentityRules2 returns the final identity & misc AWS rules (421-430).
func Identity2Rules() []ir.Rule {
	return []ir.Rule{
		cognitoIdentityUnauth{},
		ssoAdminInlinePolicy{},
		orgNoSCPs{},
		workspacesUnencrypted{},
		secretsVersionHardcoded{},
		snsSubscriptionHTTP{},
		sagemakerDirectInternet{},
		elasticacheOpenUser{},
		neptuneNoBackup{},
		docdbNoDeletionProtection{},
	}
}

// stringList extracts a known list of strings. known=false when the value
// is unresolved, not a list, or contains any unknown element.
func stringList(r ir.Resource, name string) (vals []string, span ir.Span, present, known bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return nil, ir.Span{}, false, false
	}
	if !v.Known {
		return nil, v.Span, true, false
	}
	l, ok := v.AsList()
	if !ok {
		return nil, v.Span, true, false
	}
	out := make([]string, 0, len(l))
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return nil, v.Span, true, false
		}
		out = append(out, s)
	}
	return out, v.Span, true, true
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-421: Cognito identity pool allows unauthenticated identities
// ---------------------------------------------------------------------------

type cognitoIdentityUnauth struct{}

func (cognitoIdentityUnauth) ID() string { return "AEGIS-AWS-421" }
func (cognitoIdentityUnauth) Title() string {
	return "Cognito identity pool allows unauthenticated identities"
}
func (cognitoIdentityUnauth) Description() string {
	return "An identity pool that grants access to unauthenticated users " +
		"hands AWS credentials to anyone on the internet. Disable " +
		"allow_unauthenticated_identities unless guest access is intended."
}
func (cognitoIdentityUnauth) Severity() ir.Severity { return ir.SeverityHigh }

func (cognitoIdentityUnauth) AppliesTo(resType string) bool {
	return resType == "aws_cognito_identity_pool"
}

func (cognitoIdentityUnauth) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getBool(r, "allow_unauthenticated_identities")
	if !present || !known || !v {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-421",
		Title:       (cognitoIdentityUnauth{}).Title(),
		Description: (cognitoIdentityUnauth{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "allow_unauthenticated_identities",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "true",
			Expected:  "false (or omitted)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-422: SSO permission set with inline admin policy
// ---------------------------------------------------------------------------

type ssoAdminInlinePolicy struct{}

func (ssoAdminInlinePolicy) ID() string { return "AEGIS-AWS-422" }
func (ssoAdminInlinePolicy) Title() string {
	return "SSO permission set with inline admin policy"
}
func (ssoAdminInlinePolicy) Description() string {
	return "An inline policy granting Action \"*\" on Resource \"*\" in an " +
		"SSO permission set gives every assigned user full admin across " +
		"accounts. Scope the actions and resources."
}
func (ssoAdminInlinePolicy) Severity() ir.Severity { return ir.SeverityHigh }

func (ssoAdminInlinePolicy) AppliesTo(resType string) bool {
	return resType == "aws_ssoadmin_permission_set_inline_policy"
}

func (ssoAdminInlinePolicy) Check(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "inline_policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !inlinePolicyIsAdmin(pol) {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-422",
		Title:       (ssoAdminInlinePolicy{}).Title(),
		Description: (ssoAdminInlinePolicy{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "inline_policy",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "Allow statement with Action \"*\" (or \"*:*\") on Resource \"*\"",
			Expected:  "scoped Action and Resource lists",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-423: Organization without service control policies
// ---------------------------------------------------------------------------

type orgNoSCPs struct{}

func (orgNoSCPs) ID() string { return "AEGIS-AWS-423" }
func (orgNoSCPs) Title() string {
	return "Organization without service control policies enabled"
}
func (orgNoSCPs) Description() string {
	return "Without SERVICE_CONTROL_POLICY in enabled_policy_types the " +
		"organization cannot attach SCP guardrails, leaving member accounts " +
		"unconstrained. Absent list means the provider default, which is " +
		"not judged here."
}
func (orgNoSCPs) Severity() ir.Severity { return ir.SeverityMedium }

func (orgNoSCPs) AppliesTo(resType string) bool {
	return resType == "aws_organizations_organization"
}

func (orgNoSCPs) Check(r ir.Resource) []ir.Finding {
	types, span, present, known := stringList(r, "enabled_policy_types")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	for _, t := range types {
		if t == "SERVICE_CONTROL_POLICY" {
			return nil
		}
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-423",
		Title:       (orgNoSCPs{}).Title(),
		Description: (orgNoSCPs{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "enabled_policy_types",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "[" + strings.Join(types, ", ") + "]",
			Expected:  "list including SERVICE_CONTROL_POLICY",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-424: WorkSpaces volumes unencrypted
// ---------------------------------------------------------------------------

type workspacesUnencrypted struct{}

func (workspacesUnencrypted) ID() string { return "AEGIS-AWS-424" }
func (workspacesUnencrypted) Title() string {
	return "WorkSpaces volumes unencrypted"
}
func (workspacesUnencrypted) Description() string {
	return "WorkSpaces root or user volumes without encryption expose " +
		"desktop data at rest. Enable root_volume_encryption_enabled and " +
		"user_volume_encryption_enabled."
}
func (workspacesUnencrypted) Severity() ir.Severity { return ir.SeverityHigh }

func (workspacesUnencrypted) AppliesTo(resType string) bool {
	return resType == "aws_workspaces_workspace"
}

func (workspacesUnencrypted) Check(r ir.Resource) []ir.Finding {
	root, rootSpan, _, rootKnown := getBool(r, "root_volume_encryption_enabled")
	user, userSpan, _, userKnown := getBool(r, "user_volume_encryption_enabled")
	var which string
	var attrSpan ir.Span
	switch {
	case rootKnown && !root:
		which, attrSpan = "root_volume_encryption_enabled = false", rootSpan
	case userKnown && !user:
		which, attrSpan = "user_volume_encryption_enabled = false", userSpan
	default:
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-424",
		Title:       (workspacesUnencrypted{}).Title(),
		Description: (workspacesUnencrypted{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "volume encryption",
			Span:      evidenceSpan(attrSpan, r.Span),
			Actual:    which,
			Expected:  "root_volume_encryption_enabled and user_volume_encryption_enabled = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-425: Secrets Manager version with hardcoded secret
// ---------------------------------------------------------------------------

type secretsVersionHardcoded struct{}

func (secretsVersionHardcoded) ID() string { return "AEGIS-AWS-425" }
func (secretsVersionHardcoded) Title() string {
	return "Secrets Manager version with hardcoded secret"
}
func (secretsVersionHardcoded) Description() string {
	return "A secret_string written as a literal in Terraform config is " +
		"stored in state, plan output, and version control — defeating the " +
		"purpose of Secrets Manager. Generate it or reference it instead. " +
		"The secret value is never included in findings."
}
func (secretsVersionHardcoded) Severity() ir.Severity { return ir.SeverityHigh }

func (secretsVersionHardcoded) AppliesTo(resType string) bool {
	return resType == "aws_secretsmanager_secret_version"
}

func (secretsVersionHardcoded) Check(r ir.Resource) []ir.Finding {
	sec, span, present, known := getString(r, "secret_string")
	if !present || !known || strings.TrimSpace(sec) == "" {
		return nil // absent, unresolved, or empty: nothing hardcoded
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-425",
		Title:       (secretsVersionHardcoded{}).Title(),
		Description: (secretsVersionHardcoded{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "secret_string",
			Span:      evidenceSpan(span, r.Span),
			Actual:    "[REDACTED]",
			Expected:  "generated or externally-sourced secret, not a literal",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-426: SNS subscription over plaintext HTTP
// ---------------------------------------------------------------------------

type snsSubscriptionHTTP struct{}

func (snsSubscriptionHTTP) ID() string { return "AEGIS-AWS-426" }
func (snsSubscriptionHTTP) Title() string {
	return "SNS subscription over plaintext HTTP"
}
func (snsSubscriptionHTTP) Description() string {
	return "An SNS subscription using the http protocol delivers message " +
		"content unencrypted in transit. Use https."
}
func (snsSubscriptionHTTP) Severity() ir.Severity { return ir.SeverityHigh }

func (snsSubscriptionHTTP) AppliesTo(resType string) bool {
	return resType == "aws_sns_topic_subscription"
}

func (snsSubscriptionHTTP) Check(r ir.Resource) []ir.Finding {
	proto, span, present, known := getString(r, "protocol")
	if !present || !known {
		return nil
	}
	if strings.ToLower(strings.TrimSpace(proto)) != "http" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-426",
		Title:       (snsSubscriptionHTTP{}).Title(),
		Description: (snsSubscriptionHTTP{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "protocol",
			Span:      evidenceSpan(span, r.Span),
			Actual:    proto,
			Expected:  "https",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-427: SageMaker notebook with direct internet access
// ---------------------------------------------------------------------------

type sagemakerDirectInternet struct{}

func (sagemakerDirectInternet) ID() string { return "AEGIS-AWS-427" }
func (sagemakerDirectInternet) Title() string {
	return "SageMaker notebook with direct internet access"
}
func (sagemakerDirectInternet) Description() string {
	return "A notebook instance with direct internet access can exfiltrate " +
		"training data and download untrusted code. Disable direct internet " +
		"access and route through a VPC instead."
}
func (sagemakerDirectInternet) Severity() ir.Severity { return ir.SeverityMedium }

func (sagemakerDirectInternet) AppliesTo(resType string) bool {
	return resType == "aws_sagemaker_notebook_instance"
}

func (sagemakerDirectInternet) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getString(r, "direct_internet_access")
	if !present {
		// Optional; the AWS API default is Enabled: the notebook can reach
		// the internet directly.
		return absentInsecureDefault(sagemakerDirectInternet{}, r,
			"direct_internet_access", "absent (provider default: Enabled)", "Disabled")
	}
	if !known {
		return nil // unresolved: cannot decide
	}
	if v != "Enabled" {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-427",
		Title:       (sagemakerDirectInternet{}).Title(),
		Description: (sagemakerDirectInternet{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "direct_internet_access",
			Span:      evidenceSpan(span, r.Span),
			Actual:    v,
			Expected:  "Disabled",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-428: ElastiCache user with open access
// ---------------------------------------------------------------------------

type elasticacheOpenUser struct{}

func (elasticacheOpenUser) ID() string { return "AEGIS-AWS-428" }
func (elasticacheOpenUser) Title() string {
	return "ElastiCache user with open access string"
}
func (elasticacheOpenUser) Description() string {
	return "An ElastiCache user whose access string grants all commands " +
		"on all keys (~* with +@all) is effectively an admin credential. " +
		"Scope commands and key patterns to what the workload needs."
}
func (elasticacheOpenUser) Severity() ir.Severity { return ir.SeverityHigh }

func (elasticacheOpenUser) AppliesTo(resType string) bool {
	return resType == "aws_elasticache_user"
}

func (elasticacheOpenUser) Check(r ir.Resource) []ir.Finding {
	s, span, present, known := getString(r, "access_string")
	if !present || !known {
		return nil
	}
	if !strings.Contains(s, "~*") || !strings.Contains(s, "+@all") {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-428",
		Title:       (elasticacheOpenUser{}).Title(),
		Description: (elasticacheOpenUser{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "access_string",
			Span:      evidenceSpan(span, r.Span),
			Actual:    s,
			Expected:  "scoped commands and key patterns (no +@all with ~*)",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-429: Neptune cluster without backup retention
// ---------------------------------------------------------------------------

type neptuneNoBackup struct{}

func (neptuneNoBackup) ID() string { return "AEGIS-AWS-429" }
func (neptuneNoBackup) Title() string {
	return "Neptune cluster without backup retention"
}
func (neptuneNoBackup) Description() string {
	return "A Neptune cluster with no backup retention period cannot be " +
		"restored after data loss or corruption. Set backup_retention_period " +
		"to at least 1 day."
}
func (neptuneNoBackup) Severity() ir.Severity { return ir.SeverityMedium }

func (neptuneNoBackup) AppliesTo(resType string) bool {
	return resType == "aws_neptune_cluster"
}

func (neptuneNoBackup) Check(r ir.Resource) []ir.Finding {
	n, span, present, known := getNumber(r, "backup_retention_period")
	if !present || (known && n == 0) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-429",
			Title:       (neptuneNoBackup{}).Title(),
			Description: (neptuneNoBackup{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "backup_retention_period",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent (provider default: 1) or 0",
				Expected:  "backup_retention_period >= 1",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-430: DocumentDB cluster without deletion protection
// ---------------------------------------------------------------------------

type docdbNoDeletionProtection struct{}

func (docdbNoDeletionProtection) ID() string { return "AEGIS-AWS-430" }
func (docdbNoDeletionProtection) Title() string {
	return "DocumentDB cluster without deletion protection"
}
func (docdbNoDeletionProtection) Description() string {
	return "A DocumentDB cluster without deletion protection can be " +
		"destroyed by a single API call or Terraform change. Enable " +
		"deletion_protection."
}
func (docdbNoDeletionProtection) Severity() ir.Severity { return ir.SeverityMedium }

func (docdbNoDeletionProtection) AppliesTo(resType string) bool {
	return resType == "aws_docdb_cluster"
}

func (docdbNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	v, span, present, known := getBool(r, "deletion_protection")
	if !present || (known && !v) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-430",
			Title:       (docdbNoDeletionProtection{}).Title(),
			Description: (docdbNoDeletionProtection{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "deletion_protection",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent (provider default: disabled) or false",
				Expected:  "deletion_protection = true",
			},
		}}
	}
	return nil
}
