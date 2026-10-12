package aws

import (
	"encoding/json"
	"fmt"
	"strings"

	"aegis/internal/ir"
)

// Deep KMS & secrets rules, AEGIS-AWS-780 through AEGIS-AWS-799.
//
// Unknown-value contract: a present-but-unresolved attribute yields no
// finding. An absent attribute is judged against the provider's documented
// insecure default via absentInsecureDefault.

// ---------------------------------------------------------------------------
// AEGIS-AWS-780: KMS key rotation period longer than one year
// ---------------------------------------------------------------------------

type kmsRotationPeriodLong struct{}

func (kmsRotationPeriodLong) ID() string { return "AEGIS-AWS-780" }
func (kmsRotationPeriodLong) Title() string {
	return "KMS key rotation period longer than one year"
}
func (kmsRotationPeriodLong) Description() string {
	return "A KMS key with rotation enabled but rotation_period_in_days " +
		"above 365 keeps the same key material for over a year, " +
		"lengthening the exposure window of a compromised key. " +
		"(Rotation disabled entirely is AEGIS-AWS-335.)"
}
func (kmsRotationPeriodLong) Severity() ir.Severity { return ir.SeverityMedium }

func (kmsRotationPeriodLong) AppliesTo(resType string) bool {
	return resType == "aws_kms_key"
}

func (kmsRotationPeriodLong) Check(r ir.Resource) []ir.Finding {
	rule := kmsRotationPeriodLong{}
	rot, _, rpresent, rknown := getBool(r, "enable_key_rotation")
	if !rpresent || !rknown || !rot {
		return nil // AEGIS-AWS-335 covers disabled; unresolved: cannot decide
	}
	period, span, ppresent, pknown := getNumber(r, "rotation_period_in_days")
	if !ppresent || !pknown {
		return nil // provider default is 365; unresolved: cannot decide
	}
	if period <= 365 {
		return nil
	}
	return msgFinding(rule, r, "rotation_period_in_days", span,
		fmt.Sprintf("%.0f days", period), "<= 365 days")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-781: KMS key with short deletion window
// ---------------------------------------------------------------------------

type kmsDeletionWindowShort struct{}

func (kmsDeletionWindowShort) ID() string { return "AEGIS-AWS-781" }
func (kmsDeletionWindowShort) Title() string {
	return "KMS key with short deletion window"
}
func (kmsDeletionWindowShort) Description() string {
	return "A KMS key with deletion_window_in_days below the 30-day " +
		"default leaves almost no time to notice and cancel an " +
		"accidental or malicious key deletion."
}
func (kmsDeletionWindowShort) Severity() ir.Severity { return ir.SeverityLow }

func (kmsDeletionWindowShort) AppliesTo(resType string) bool {
	return resType == "aws_kms_key"
}

func (kmsDeletionWindowShort) Check(r ir.Resource) []ir.Finding {
	rule := kmsDeletionWindowShort{}
	days, span, present, known := getNumber(r, "deletion_window_in_days")
	if !present || !known {
		return nil // provider default is 30; unresolved: cannot decide
	}
	if days >= 30 {
		return nil
	}
	return msgFinding(rule, r, "deletion_window_in_days", span,
		fmt.Sprintf("%.0f days", days), ">= 30 days")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-782: KMS key policy allows public principal
// ---------------------------------------------------------------------------

type kmsKeyPolicyPublicPrincipal struct{}

func (kmsKeyPolicyPublicPrincipal) ID() string { return "AEGIS-AWS-782" }
func (kmsKeyPolicyPublicPrincipal) Title() string {
	return "KMS key policy allows public principal"
}
func (kmsKeyPolicyPublicPrincipal) Description() string {
	return "A KMS key policy Allow statement with Principal \"*\" grants " +
		"anonymous key use to the world. Key policies should name " +
		"specific AWS principals."
}
func (kmsKeyPolicyPublicPrincipal) Severity() ir.Severity { return ir.SeverityHigh }

func (kmsKeyPolicyPublicPrincipal) AppliesTo(resType string) bool {
	return resType == "aws_kms_key"
}

func (kmsKeyPolicyPublicPrincipal) Check(r ir.Resource) []ir.Finding {
	rule := kmsKeyPolicyPublicPrincipal{}
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if policyAllowsPublicPrincipal(doc) {
		return msgFinding(rule, r, "policy", span,
			"Allow statement with Principal \"*\"",
			"Principal scoped to specific AWS principals")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-783: KMS key without description
// ---------------------------------------------------------------------------

type kmsKeyNoDescription struct{}

func (kmsKeyNoDescription) ID() string { return "AEGIS-AWS-783" }
func (kmsKeyNoDescription) Title() string {
	return "KMS key without description"
}
func (kmsKeyNoDescription) Description() string {
	return "A KMS key with no description is unidentifiable in audits and " +
		"key inventories. Describe the key's purpose and owner."
}
func (kmsKeyNoDescription) Severity() ir.Severity { return ir.SeverityLow }

func (kmsKeyNoDescription) AppliesTo(resType string) bool {
	return resType == "aws_kms_key"
}

func (kmsKeyNoDescription) Check(r ir.Resource) []ir.Finding {
	rule := kmsKeyNoDescription{}
	desc, span, present, known := getString(r, "description")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(desc) != "" {
		return nil
	}
	actual := "absent"
	if present {
		actual = "empty"
	}
	return msgFinding(rule, r, "description", span, actual, "description of the key's purpose")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-784: KMS external key without key material expiry
// ---------------------------------------------------------------------------

type kmsExternalKeyNoExpiry struct{}

func (kmsExternalKeyNoExpiry) ID() string { return "AEGIS-AWS-784" }
func (kmsExternalKeyNoExpiry) Title() string {
	return "KMS external key without key material expiry"
}
func (kmsExternalKeyNoExpiry) Description() string {
	return "An external KMS key with no valid_to never expires its " +
		"imported key material, so a compromised external key stays " +
		"usable indefinitely. Set valid_to to bound the material's " +
		"lifetime."
}
func (kmsExternalKeyNoExpiry) Severity() ir.Severity { return ir.SeverityLow }

func (kmsExternalKeyNoExpiry) AppliesTo(resType string) bool {
	return resType == "aws_kms_external_key"
}

func (kmsExternalKeyNoExpiry) Check(r ir.Resource) []ir.Finding {
	rule := kmsExternalKeyNoExpiry{}
	validTo, span, present, known := getString(r, "valid_to")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(validTo) != "" {
		return nil
	}
	actual := "absent (key material never expires)"
	if present {
		actual = "empty"
	}
	return msgFinding(rule, r, "valid_to", span, actual, "valid_to timestamp bounding key material lifetime")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-785: KMS key bypasses policy lockout safety check
// ---------------------------------------------------------------------------

type kmsBypassLockoutSafetyCheck struct{}

func (kmsBypassLockoutSafetyCheck) ID() string { return "AEGIS-AWS-785" }
func (kmsBypassLockoutSafetyCheck) Title() string {
	return "KMS key bypasses policy lockout safety check"
}
func (kmsBypassLockoutSafetyCheck) Description() string {
	return "Setting bypass_policy_lockout_safety_check = true disables " +
		"the guardrail that rejects key policies which would lock every " +
		"principal, including the account root, out of the key. A bad " +
		"policy then bricks the key permanently."
}
func (kmsBypassLockoutSafetyCheck) Severity() ir.Severity { return ir.SeverityHigh }

func (kmsBypassLockoutSafetyCheck) AppliesTo(resType string) bool {
	return resType == "aws_kms_key"
}

func (kmsBypassLockoutSafetyCheck) Check(r ir.Resource) []ir.Finding {
	rule := kmsBypassLockoutSafetyCheck{}
	bypass, span, present, known := getBool(r, "bypass_policy_lockout_safety_check")
	if !present || !known {
		return nil // provider default is false; unresolved: cannot decide
	}
	if !bypass {
		return nil
	}
	return msgFinding(rule, r, "bypass_policy_lockout_safety_check", span,
		"true", "false (keep the lockout safety check)")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-786: EBS default encryption uses AWS-managed key
// ---------------------------------------------------------------------------

type ebsDefaultKMSAWSManaged struct{}

func (ebsDefaultKMSAWSManaged) ID() string { return "AEGIS-AWS-786" }
func (ebsDefaultKMSAWSManaged) Title() string {
	return "EBS default encryption uses AWS-managed key"
}
func (ebsDefaultKMSAWSManaged) Description() string {
	return "An aws_ebs_default_kms_key explicitly set to alias/aws/ebs " +
		"keeps default EBS encryption on the AWS-managed key, which the " +
		"account cannot rotate or control via key policy. Point it at a " +
		"customer-managed key. (Default encryption disabled is " +
		"AEGIS-AWS-391.)"
}
func (ebsDefaultKMSAWSManaged) Severity() ir.Severity { return ir.SeverityMedium }

func (ebsDefaultKMSAWSManaged) AppliesTo(resType string) bool {
	return resType == "aws_ebs_default_kms_key"
}

func (ebsDefaultKMSAWSManaged) Check(r ir.Resource) []ir.Finding {
	rule := ebsDefaultKMSAWSManaged{}
	key, span, present, known := getString(r, "key_arn")
	if !present || !known {
		return nil // required attribute; unresolved: cannot decide
	}
	if isAWSManagedKeyAlias(strings.TrimSpace(key), "alias/aws/ebs") {
		return msgFinding(rule, r, "key_arn", span,
			strings.TrimSpace(key), "customer-managed KMS key ARN")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-787: Secrets Manager secret using AWS-managed encryption key
// ---------------------------------------------------------------------------

type secretsManagerAWSManagedKey struct{}

func (secretsManagerAWSManagedKey) ID() string { return "AEGIS-AWS-787" }
func (secretsManagerAWSManagedKey) Title() string {
	return "Secrets Manager secret using AWS-managed encryption key"
}
func (secretsManagerAWSManagedKey) Description() string {
	return "A secret with kms_key_id explicitly set to " +
		"alias/aws/secretsmanager encrypts with the AWS-managed key, " +
		"which the account cannot rotate or control via key policy. Use " +
		"a customer-managed key. (Missing kms_key_id is AEGIS-AWS-563.)"
}
func (secretsManagerAWSManagedKey) Severity() ir.Severity { return ir.SeverityMedium }

func (secretsManagerAWSManagedKey) AppliesTo(resType string) bool {
	return resType == "aws_secretsmanager_secret"
}

func (secretsManagerAWSManagedKey) Check(r ir.Resource) []ir.Finding {
	rule := secretsManagerAWSManagedKey{}
	key, span, present, known := getString(r, "kms_key_id")
	if !present || !known {
		return nil // AEGIS-AWS-563 covers absent; unresolved: cannot decide
	}
	if isAWSManagedKeyAlias(strings.TrimSpace(key), "alias/aws/secretsmanager") {
		return msgFinding(rule, r, "kms_key_id", span,
			strings.TrimSpace(key), "customer-managed KMS key")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-788: Secrets Manager rotation interval above 30 days
// ---------------------------------------------------------------------------

type secretsRotationAbove30Days struct{}

func (secretsRotationAbove30Days) ID() string { return "AEGIS-AWS-788" }
func (secretsRotationAbove30Days) Title() string {
	return "Secrets Manager rotation interval above 30 days"
}
func (secretsRotationAbove30Days) Description() string {
	return "A Secrets Manager rotation interval between 31 and 90 days " +
		"keeps a compromised credential usable for over a month. Rotate " +
		"at least monthly. (Intervals above 90 days are AEGIS-AWS-337.)"
}
func (secretsRotationAbove30Days) Severity() ir.Severity { return ir.SeverityMedium }

func (secretsRotationAbove30Days) AppliesTo(resType string) bool {
	return resType == "aws_secretsmanager_secret_rotation"
}

func (secretsRotationAbove30Days) Check(r ir.Resource) []ir.Finding {
	rule := secretsRotationAbove30Days{}
	ruleBlks, _, present, known := getBlocks(r, "rotation_rules")
	if !present || !known {
		return nil // no rotation rules configured: cannot evaluate the interval
	}
	for _, b := range ruleBlks {
		days, span, dpresent, dknown := blockNumber(b, "automatically_after_days")
		if !dpresent || !dknown {
			continue // unresolved interval: cannot decide
		}
		if days > 30 && days <= 90 {
			return msgFinding(rule, r, "rotation_rules.automatically_after_days",
				span, fmt.Sprintf("%.0f days", days), "<= 30 days")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-789: Secrets Manager secret without description
// ---------------------------------------------------------------------------

type secretsManagerNoDescription struct{}

func (secretsManagerNoDescription) ID() string { return "AEGIS-AWS-789" }
func (secretsManagerNoDescription) Title() string {
	return "Secrets Manager secret without description"
}
func (secretsManagerNoDescription) Description() string {
	return "A secret with no description is unidentifiable in audits and " +
		"secret inventories. Describe the secret's purpose and owner."
}
func (secretsManagerNoDescription) Severity() ir.Severity { return ir.SeverityLow }

func (secretsManagerNoDescription) AppliesTo(resType string) bool {
	return resType == "aws_secretsmanager_secret"
}

func (secretsManagerNoDescription) Check(r ir.Resource) []ir.Finding {
	rule := secretsManagerNoDescription{}
	desc, span, present, known := getString(r, "description")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(desc) != "" {
		return nil
	}
	actual := "absent"
	if present {
		actual = "empty"
	}
	return msgFinding(rule, r, "description", span, actual, "description of the secret's purpose")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-790: SSM SecureString parameter using default KMS key
// ---------------------------------------------------------------------------

type ssmSecureStringDefaultKey struct{}

func (ssmSecureStringDefaultKey) ID() string { return "AEGIS-AWS-790" }
func (ssmSecureStringDefaultKey) Title() string {
	return "SSM SecureString parameter using default KMS key"
}
func (ssmSecureStringDefaultKey) Description() string {
	return "A SecureString parameter with no key_id encrypts with the " +
		"default aws/ssm key, which the account cannot rotate or scope " +
		"via key policy. Point key_id at a customer-managed key."
}
func (ssmSecureStringDefaultKey) Severity() ir.Severity { return ir.SeverityLow }

func (ssmSecureStringDefaultKey) AppliesTo(resType string) bool {
	return resType == "aws_ssm_parameter"
}

func (ssmSecureStringDefaultKey) Check(r ir.Resource) []ir.Finding {
	rule := ssmSecureStringDefaultKey{}
	typ, _, tpresent, tknown := getString(r, "type")
	if !tpresent || !tknown || !strings.EqualFold(strings.TrimSpace(typ), "SecureString") {
		return nil // not a SecureString (or unresolved): nothing to judge
	}
	key, span, present, known := getString(r, "key_id")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(key) != "" {
		return nil
	}
	actual := "absent (default aws/ssm key)"
	if present {
		actual = "empty"
	}
	return msgFinding(rule, r, "key_id", span, actual, "key_id set to a customer-managed KMS key")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-791: SSM StringList parameter stores plaintext secret
// ---------------------------------------------------------------------------

type ssmStringListPlaintextSecret struct{}

func (ssmStringListPlaintextSecret) ID() string { return "AEGIS-AWS-791" }
func (ssmStringListPlaintextSecret) Title() string {
	return "SSM StringList parameter stores plaintext secret"
}
func (ssmStringListPlaintextSecret) Description() string {
	return "An SSM parameter whose name suggests a secret but whose type " +
		"is StringList (not SecureString) stores the values unencrypted. " +
		"(Plain String secrets are AEGIS-AWS-338.)"
}
func (ssmStringListPlaintextSecret) Severity() ir.Severity { return ir.SeverityMedium }

func (ssmStringListPlaintextSecret) AppliesTo(resType string) bool {
	return resType == "aws_ssm_parameter"
}

func (ssmStringListPlaintextSecret) Check(r ir.Resource) []ir.Finding {
	rule := ssmStringListPlaintextSecret{}
	typ, _, tpresent, tknown := getString(r, "type")
	if !tpresent || !tknown || !strings.EqualFold(strings.TrimSpace(typ), "StringList") {
		return nil // not a StringList (or unresolved): nothing to judge
	}
	name, span, npresent, nknown := getString(r, "name")
	if !npresent || !nknown {
		return nil // unresolved: cannot decide
	}
	if !secretLikeName(name) {
		return nil
	}
	return msgFinding(rule, r, "type", evidenceSpan(span, r.Span),
		"StringList with secret-like name (plaintext)", "type = \"SecureString\"")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-792: SSM document shared publicly
// ---------------------------------------------------------------------------

type ssmDocumentPublicSharing struct{}

func (ssmDocumentPublicSharing) ID() string { return "AEGIS-AWS-792" }
func (ssmDocumentPublicSharing) Title() string {
	return "SSM document shared publicly"
}
func (ssmDocumentPublicSharing) Description() string {
	return "An SSM document with permissions account_ids = [\"all\"] is " +
		"shared with every AWS account, exposing its automation content " +
		"and any embedded commands publicly."
}
func (ssmDocumentPublicSharing) Severity() ir.Severity { return ir.SeverityHigh }

func (ssmDocumentPublicSharing) AppliesTo(resType string) bool {
	return resType == "aws_ssm_document"
}

func (ssmDocumentPublicSharing) Check(r ir.Resource) []ir.Finding {
	rule := ssmDocumentPublicSharing{}
	permBlks, span, present, known := getBlocks(r, "permissions")
	if !present || !known {
		return nil // unresolved: cannot decide
	}
	for _, b := range permBlks {
		ids, allKnown := blockStrings(b, "account_ids")
		if !allKnown {
			continue // unresolved: cannot decide
		}
		if findStringFold(ids, "all") {
			return msgFinding(rule, r, "permissions.account_ids",
				evidenceSpan(span, r.Span),
				"\"all\" (public)", "explicit AWS account IDs")
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-793: Secrets Manager secret version with weak placeholder secret
// ---------------------------------------------------------------------------

type secretsManagerWeakSecret struct{}

func (secretsManagerWeakSecret) ID() string { return "AEGIS-AWS-793" }
func (secretsManagerWeakSecret) Title() string {
	return "Secrets Manager secret version with weak placeholder secret"
}
func (secretsManagerWeakSecret) Description() string {
	return "A secret version whose secret_string is a well-known " +
		"placeholder (\"changeme\", \"password\", ...) is a guessable " +
		"credential. Only exact placeholder matches are flagged; genuine " +
		"secret values are never judged. The value itself is never " +
		"included in findings."
}
func (secretsManagerWeakSecret) Severity() ir.Severity { return ir.SeverityHigh }

func (secretsManagerWeakSecret) AppliesTo(resType string) bool {
	return resType == "aws_secretsmanager_secret_version"
}

func (secretsManagerWeakSecret) Check(r ir.Resource) []ir.Finding {
	rule := secretsManagerWeakSecret{}
	sec, span, present, known := getString(r, "secret_string")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if secretStringHasWeakPlaceholder(sec) {
		return msgFinding(rule, r, "secret_string", span,
			"well-known placeholder credential", "unique generated secret")
	}
	return nil
}

// weakSecretPlaceholders are exact (case-insensitive) matches only. Any
// other value is assumed to be a genuine secret the resource is meant to
// hold, and flagging it would be noise.
var weakSecretPlaceholders = []string{
	"password", "changeme", "change-me", "test", "test123", "example",
	"secret", "123456", "admin", "default", "password123", "qwerty",
	"letmein",
}

func secretValueIsWeakPlaceholder(v string) bool {
	t := strings.ToLower(strings.TrimSpace(v))
	for _, w := range weakSecretPlaceholders {
		if t == w {
			return true
		}
	}
	return false
}

// secretStringHasWeakPlaceholder checks a secret_string value: a plain
// string is tested directly; a JSON object has each string member tested.
func secretStringHasWeakPlaceholder(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return false
	}
	if strings.HasPrefix(t, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(t), &obj); err != nil {
			return secretValueIsWeakPlaceholder(t)
		}
		for _, v := range obj {
			if str, ok := v.(string); ok && secretValueIsWeakPlaceholder(str) {
				return true
			}
		}
		return false
	}
	return secretValueIsWeakPlaceholder(t)
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-794: KMS grant with decrypt and retire-grant operations
// ---------------------------------------------------------------------------

type kmsGrantDecryptRetire struct{}

func (kmsGrantDecryptRetire) ID() string { return "AEGIS-AWS-794" }
func (kmsGrantDecryptRetire) Title() string {
	return "KMS grant with decrypt and retire-grant operations"
}
func (kmsGrantDecryptRetire) Description() string {
	return "A KMS grant combining Decrypt with RetireGrant lets the " +
		"grantee both decrypt data and retire grants, a privileged " +
		"combination that should be split across least-privilege grants. " +
		"(Wildcard operations are AEGIS-AWS-562.)"
}
func (kmsGrantDecryptRetire) Severity() ir.Severity { return ir.SeverityLow }

func (kmsGrantDecryptRetire) AppliesTo(resType string) bool {
	return resType == "aws_kms_grant"
}

func (kmsGrantDecryptRetire) Check(r ir.Resource) []ir.Finding {
	rule := kmsGrantDecryptRetire{}
	v, ok := r.Attributes["operations"]
	if !ok || !v.Known {
		return nil // absent or unresolved: cannot decide
	}
	l, ok := v.AsList()
	if !ok {
		return nil // unexpected shape: cannot decide
	}
	var hasDecrypt, hasRetire bool
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			continue // unresolved element: cannot confirm the combination
		}
		switch strings.TrimSpace(s) {
		case "Decrypt":
			hasDecrypt = true
		case "RetireGrant":
			hasRetire = true
		}
	}
	if hasDecrypt && hasRetire {
		return msgFinding(rule, r, "operations", evidenceSpan(v.Span, r.Span),
			"Decrypt + RetireGrant", "least-privilege operation set")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-795: KMS grant to public grantee principal
// ---------------------------------------------------------------------------

type kmsGrantPublicGrantee struct{}

func (kmsGrantPublicGrantee) ID() string { return "AEGIS-AWS-795" }
func (kmsGrantPublicGrantee) Title() string {
	return "KMS grant to public grantee principal"
}
func (kmsGrantPublicGrantee) Description() string {
	return "A KMS grant with grantee_principal = \"*\" delegates key " +
		"operations to every principal, effectively public key access."
}
func (kmsGrantPublicGrantee) Severity() ir.Severity { return ir.SeverityHigh }

func (kmsGrantPublicGrantee) AppliesTo(resType string) bool {
	return resType == "aws_kms_grant"
}

func (kmsGrantPublicGrantee) Check(r ir.Resource) []ir.Finding {
	rule := kmsGrantPublicGrantee{}
	gp, span, present, known := getString(r, "grantee_principal")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if strings.TrimSpace(gp) != "*" {
		return nil
	}
	return msgFinding(rule, r, "grantee_principal", span,
		"\"*\"", "specific grantee principal ARN")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-796: Secrets Manager secret policy allows public principal
// ---------------------------------------------------------------------------

type secretsManagerPolicyPublic struct{}

func (secretsManagerPolicyPublic) ID() string { return "AEGIS-AWS-796" }
func (secretsManagerPolicyPublic) Title() string {
	return "Secrets Manager secret policy allows public principal"
}
func (secretsManagerPolicyPublic) Description() string {
	return "A secret resource policy Allow statement with Principal " +
		"\"*\" grants anonymous access to the secret value."
}
func (secretsManagerPolicyPublic) Severity() ir.Severity { return ir.SeverityHigh }

func (secretsManagerPolicyPublic) AppliesTo(resType string) bool {
	return resType == "aws_secretsmanager_secret_policy"
}

func (secretsManagerPolicyPublic) Check(r ir.Resource) []ir.Finding {
	rule := secretsManagerPolicyPublic{}
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if policyAllowsPublicPrincipal(doc) {
		return msgFinding(rule, r, "policy", span,
			"Allow statement with Principal \"*\"",
			"Principal scoped to specific AWS principals")
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-797: SSM parameter under reserved /aws/ prefix
// ---------------------------------------------------------------------------

type ssmParameterReservedPrefix struct{}

func (ssmParameterReservedPrefix) ID() string { return "AEGIS-AWS-797" }
func (ssmParameterReservedPrefix) Title() string {
	return "SSM parameter under reserved /aws/ prefix"
}
func (ssmParameterReservedPrefix) Description() string {
	return "Parameter names under /aws/ are reserved for AWS services. " +
		"A user parameter there can collide with service-managed " +
		"parameters and behave unexpectedly."
}
func (ssmParameterReservedPrefix) Severity() ir.Severity { return ir.SeverityLow }

func (ssmParameterReservedPrefix) AppliesTo(resType string) bool {
	return resType == "aws_ssm_parameter"
}

func (ssmParameterReservedPrefix) Check(r ir.Resource) []ir.Finding {
	rule := ssmParameterReservedPrefix{}
	name, span, present, known := getString(r, "name")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !strings.HasPrefix(strings.TrimSpace(name), "/aws/") {
		return nil
	}
	return msgFinding(rule, r, "name", span,
		strings.TrimSpace(name), "parameter name outside the reserved /aws/ prefix")
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-798: KMS key policy statement without Sid
// ---------------------------------------------------------------------------

type kmsKeyPolicyStatementNoSid struct{}

func (kmsKeyPolicyStatementNoSid) ID() string { return "AEGIS-AWS-798" }
func (kmsKeyPolicyStatementNoSid) Title() string {
	return "KMS key policy statement without Sid"
}
func (kmsKeyPolicyStatementNoSid) Description() string {
	return "A KMS key policy statement with no Sid is harder to audit, " +
		"reference, and review for intent. Give every statement a " +
		"descriptive Sid."
}
func (kmsKeyPolicyStatementNoSid) Severity() ir.Severity { return ir.SeverityLow }

func (kmsKeyPolicyStatementNoSid) AppliesTo(resType string) bool {
	return resType == "aws_kms_key"
}

func (kmsKeyPolicyStatementNoSid) Check(r ir.Resource) []ir.Finding {
	rule := kmsKeyPolicyStatementNoSid{}
	doc, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if policyStatementMissingSid(doc) {
		return msgFinding(rule, r, "policy", span,
			"statement without Sid", "every statement carries a descriptive Sid")
	}
	return nil
}

// policyStatementMissingSid reports whether any statement in a policy JSON
// document lacks a non-empty Sid. Malformed JSON yields false.
func policyStatementMissingSid(doc string) bool {
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
		sid, _ := s["Sid"].(string)
		if strings.TrimSpace(sid) == "" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-799: Secrets Manager secret with zero recovery window
// ---------------------------------------------------------------------------

type secretsManagerZeroRecoveryWindow struct{}

func (secretsManagerZeroRecoveryWindow) ID() string { return "AEGIS-AWS-799" }
func (secretsManagerZeroRecoveryWindow) Title() string {
	return "Secrets Manager secret with zero recovery window"
}
func (secretsManagerZeroRecoveryWindow) Description() string {
	return "A secret with recovery_window_in_days = 0 is deleted " +
		"immediately with no recovery window: an accidental deletion is " +
		"irreversible and breaks every dependent workload at once."
}
func (secretsManagerZeroRecoveryWindow) Severity() ir.Severity { return ir.SeverityHigh }

func (secretsManagerZeroRecoveryWindow) AppliesTo(resType string) bool {
	return resType == "aws_secretsmanager_secret"
}

func (secretsManagerZeroRecoveryWindow) Check(r ir.Resource) []ir.Finding {
	rule := secretsManagerZeroRecoveryWindow{}
	days, span, present, known := getNumber(r, "recovery_window_in_days")
	if !present || !known {
		return nil // provider default is 30; unresolved: cannot decide
	}
	if days != 0 {
		return nil
	}
	return msgFinding(rule, r, "recovery_window_in_days", span,
		"0 (immediate deletion)", ">= 7 days")
}

// KMSSecretsDeepRules returns the deep KMS & secrets rules, in ID order.
func KMSSecretsDeepRules() []ir.Rule {
	return []ir.Rule{
		kmsRotationPeriodLong{},            // AEGIS-AWS-780
		kmsDeletionWindowShort{},           // AEGIS-AWS-781
		kmsKeyPolicyPublicPrincipal{},      // AEGIS-AWS-782
		kmsKeyNoDescription{},              // AEGIS-AWS-783
		kmsExternalKeyNoExpiry{},           // AEGIS-AWS-784
		kmsBypassLockoutSafetyCheck{},      // AEGIS-AWS-785
		ebsDefaultKMSAWSManaged{},          // AEGIS-AWS-786
		secretsManagerAWSManagedKey{},      // AEGIS-AWS-787
		secretsRotationAbove30Days{},       // AEGIS-AWS-788
		secretsManagerNoDescription{},      // AEGIS-AWS-789
		ssmSecureStringDefaultKey{},        // AEGIS-AWS-790
		ssmStringListPlaintextSecret{},     // AEGIS-AWS-791
		ssmDocumentPublicSharing{},         // AEGIS-AWS-792
		secretsManagerWeakSecret{},         // AEGIS-AWS-793
		kmsGrantDecryptRetire{},            // AEGIS-AWS-794
		kmsGrantPublicGrantee{},            // AEGIS-AWS-795
		secretsManagerPolicyPublic{},       // AEGIS-AWS-796
		ssmParameterReservedPrefix{},       // AEGIS-AWS-797
		kmsKeyPolicyStatementNoSid{},       // AEGIS-AWS-798
		secretsManagerZeroRecoveryWindow{}, // AEGIS-AWS-799
	}
}
