package aws

import (
	"encoding/json"
	"sort"
	"strings"

	"aegis/internal/ir"
)

// IdentityRules returns the identity & governance rules (AEGIS-AWS-333..340)
// in ID order. The parent wires this into the AWS pack.
func IdentityRules() []ir.Rule {
	return []ir.Rule{
		inlineAdminPolicyRule{},
		weakPasswordPolicy{},
		kmsNoRotation{},
		cloudtrailNotMultiRegion{},
		secretsRotationInterval{},
		ssmPlaintextSecret{},
		hardcodedCredentials{},
		cloudtrailNoGlobalEvents{},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-333: Inline admin policy attached to role/user/group
// ---------------------------------------------------------------------------

type inlineAdminPolicyRule struct{}

func (inlineAdminPolicyRule) ID() string { return "AEGIS-AWS-333" }
func (inlineAdminPolicyRule) Title() string {
	return "Inline admin policy attached to role/user/group"
}
func (inlineAdminPolicyRule) Description() string {
	return "An inline IAM policy with an Allow statement granting Action \"*\" " +
		"(or \"*:*\") on Resource \"*\" is administrative access. Inline policies " +
		"are harder to audit than managed ones; scope them to least privilege."
}
func (inlineAdminPolicyRule) Severity() ir.Severity { return ir.SeverityHigh }

func (inlineAdminPolicyRule) AppliesTo(resType string) bool {
	return resType == "aws_iam_role_policy" ||
		resType == "aws_iam_user_policy" ||
		resType == "aws_iam_group_policy"
}

func (inlineAdminPolicyRule) Check(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "policy")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if inlinePolicyIsAdmin(pol) {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-333",
			Title:       (inlineAdminPolicyRule{}).Title(),
			Description: (inlineAdminPolicyRule{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "policy",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "Allow statement with Action \"*\" (or \"*:*\") on Resource \"*\"",
				Expected:  "scoped Action and Resource lists",
			},
		}}
	}
	return nil
}

// inlinePolicyIsAdmin parses a policy JSON document and reports whether any
// Allow statement has Action "*" (or "*:*") with Resource "*". Action and
// Resource may each be a string or a list. Malformed JSON or unexpected
// shapes yield false (cannot decide -> no finding).
func inlinePolicyIsAdmin(doc string) bool {
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
		if actionIsStar(s["Action"]) && resourceIsStar(s["Resource"]) {
			return true
		}
	}
	return false
}

// actionIsStar reports whether v is "*", "*:*", or a list containing either.
func actionIsStar(v any) bool {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		return s == "*" || s == "*:*"
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok {
				s = strings.TrimSpace(s)
				if s == "*" || s == "*:*" {
					return true
				}
			}
		}
	}
	return false
}

// resourceIsStar reports whether v is "*" or a list containing "*".
func resourceIsStar(v any) bool {
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

// ---------------------------------------------------------------------------
// AEGIS-AWS-334: Weak or absent account password policy
// ---------------------------------------------------------------------------

type weakPasswordPolicy struct{}

func (weakPasswordPolicy) ID() string { return "AEGIS-AWS-334" }
func (weakPasswordPolicy) Title() string {
	return "Weak or absent account password policy"
}
func (weakPasswordPolicy) Description() string {
	return "The IAM account password policy is the baseline for human " +
		"credentials. A short minimum length, missing character-class " +
		"requirements, or disabled password-reuse prevention weakens every " +
		"console login in the account."
}
func (weakPasswordPolicy) Severity() ir.Severity { return ir.SeverityMedium }

func (weakPasswordPolicy) AppliesTo(resType string) bool {
	return resType == "aws_iam_account_password_policy"
}

// passwordWeakness returns the first weakness found as (attribute, actual,
// expected, span). Any one weakness yields exactly one finding.
func passwordWeakness(r ir.Resource) (attr, actual, expected string, span ir.Span, weak bool) {
	if length, lspan, present, known := getNumber(r, "minimum_password_length"); !present || (known && length < 14) {
		return "minimum_password_length", "absent or < 14", ">= 14", lspan, true
	}
	for _, name := range []string{
		"require_lowercase_characters",
		"require_uppercase_characters",
		"require_numbers",
		"require_symbols",
	} {
		if v, bspan, _, known := getBool(r, name); known && !v {
			return name, "false", "true", bspan, true
		}
	}
	if reuse, rspan, present, known := getNumber(r, "password_reuse_prevention"); !present || (known && reuse == 0) {
		return "password_reuse_prevention", "absent or 0", ">= 1 (ideally >= 5)", rspan, true
	}
	return "", "", "", ir.Span{}, false
}

func (weakPasswordPolicy) Check(r ir.Resource) []ir.Finding {
	attr, actual, expected, span, weak := passwordWeakness(r)
	if !weak {
		return nil
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-334",
		Title:       (weakPasswordPolicy{}).Title(),
		Description: (weakPasswordPolicy{}).Description(),
		Severity:    ir.SeverityMedium,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-335: KMS key without rotation
// ---------------------------------------------------------------------------

type kmsNoRotation struct{}

func (kmsNoRotation) ID() string { return "AEGIS-AWS-335" }
func (kmsNoRotation) Title() string {
	return "KMS key without rotation"
}
func (kmsNoRotation) Description() string {
	return "Customer-managed KMS keys should rotate annually. " +
		"enable_key_rotation defaults to false. (AWS-managed keys rotate " +
		"automatically and cannot set this flag; a narrow false positive is " +
		"possible if an AWS-managed key is declared explicitly.)"
}
func (kmsNoRotation) Severity() ir.Severity { return ir.SeverityHigh }

func (kmsNoRotation) AppliesTo(resType string) bool { return resType == "aws_kms_key" }

func (kmsNoRotation) Check(r ir.Resource) []ir.Finding {
	rot, span, present, known := getBool(r, "enable_key_rotation")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || !rot {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-335",
			Title:       (kmsNoRotation{}).Title(),
			Description: (kmsNoRotation{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "enable_key_rotation",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent or false (provider default: disabled)",
				Expected:  "true",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-336: CloudTrail not multi-region
// ---------------------------------------------------------------------------

type cloudtrailNotMultiRegion struct{}

func (cloudtrailNotMultiRegion) ID() string { return "AEGIS-AWS-336" }
func (cloudtrailNotMultiRegion) Title() string {
	return "CloudTrail not multi-region"
}
func (cloudtrailNotMultiRegion) Description() string {
	return "A single-region trail misses API activity in every other region. " +
		"is_multi_region_trail defaults to false."
}
func (cloudtrailNotMultiRegion) Severity() ir.Severity { return ir.SeverityHigh }

func (cloudtrailNotMultiRegion) AppliesTo(resType string) bool {
	return resType == "aws_cloudtrail"
}

func (cloudtrailNotMultiRegion) Check(r ir.Resource) []ir.Finding {
	multi, span, present, known := getBool(r, "is_multi_region_trail")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if !present || !multi {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-336",
			Title:       (cloudtrailNotMultiRegion{}).Title(),
			Description: (cloudtrailNotMultiRegion{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "is_multi_region_trail",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "absent or false (provider default: single region)",
				Expected:  "true",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-337: Secrets Manager rotation interval too long
// ---------------------------------------------------------------------------

type secretsRotationInterval struct{}

func (secretsRotationInterval) ID() string { return "AEGIS-AWS-337" }
func (secretsRotationInterval) Title() string {
	return "Secrets Manager rotation interval too long"
}
func (secretsRotationInterval) Description() string {
	return "A Secrets Manager rotation interval above 90 days keeps a " +
		"compromised credential usable for too long. Rotation cadence is " +
		"configured on aws_secretsmanager_secret_rotation via rotation_rules."
}
func (secretsRotationInterval) Severity() ir.Severity { return ir.SeverityMedium }

func (secretsRotationInterval) AppliesTo(resType string) bool {
	return resType == "aws_secretsmanager_secret_rotation"
}

// blockNumber reads a numeric attribute from a nested block map.
func blockNumber(m map[string]ir.Value, name string) (float64, ir.Span, bool, bool) {
	v, ok := m[name]
	if !ok {
		return 0, ir.Span{}, false, false
	}
	if !v.Known {
		return 0, v.Span, true, false
	}
	f, ok := v.Raw.(float64)
	if !ok {
		return 0, v.Span, true, false
	}
	return f, v.Span, true, true
}

func (secretsRotationInterval) Check(r ir.Resource) []ir.Finding {
	ruleBlks, _, present, known := getBlocks(r, "rotation_rules")
	if !present || !known {
		return nil // no rotation rules configured: cannot evaluate the interval
	}
	for _, b := range ruleBlks {
		days, span, dpresent, dknown := blockNumber(b, "automatically_after_days")
		if !dpresent || !dknown {
			continue // unresolved interval: cannot decide
		}
		if days > 90 {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-337",
				Title:       (secretsRotationInterval{}).Title(),
				Description: (secretsRotationInterval{}).Description(),
				Severity:    ir.SeverityMedium,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "rotation_rules.automatically_after_days",
					Span:      evidenceSpan(span, r.Span),
					Actual:    "rotation interval above 90 days",
					Expected:  "<= 90 days",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-338: SSM parameter stores plaintext secret
// ---------------------------------------------------------------------------

type ssmPlaintextSecret struct{}

func (ssmPlaintextSecret) ID() string { return "AEGIS-AWS-338" }
func (ssmPlaintextSecret) Title() string {
	return "SSM parameter stores plaintext secret"
}
func (ssmPlaintextSecret) Description() string {
	return "An SSM parameter whose name suggests a secret but whose type is " +
		"plain String (not SecureString) stores the value unencrypted. " +
		"The value itself is never included in findings; it is redacted by " +
		"the report layer."
}
func (ssmPlaintextSecret) Severity() ir.Severity { return ir.SeverityHigh }

func (ssmPlaintextSecret) AppliesTo(resType string) bool {
	return resType == "aws_ssm_parameter"
}

var secretNameHints = []string{
	"password", "passwd", "secret", "token", "apikey", "api_key",
}

func secretLikeName(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range secretNameHints {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func (ssmPlaintextSecret) Check(r ir.Resource) []ir.Finding {
	typ, tspan, tpresent, tknown := getString(r, "type")
	if !tpresent || !tknown || !strings.EqualFold(strings.TrimSpace(typ), "String") {
		return nil // SecureString (or unresolved): not plaintext
	}
	name, _, npresent, nknown := getString(r, "name")
	if !npresent || !nknown || !secretLikeName(name) {
		return nil // name does not suggest a secret: cannot call it one
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-338",
		Title:       (ssmPlaintextSecret{}).Title(),
		Description: (ssmPlaintextSecret{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "type",
			Span:      evidenceSpan(tspan, r.Span),
			Actual:    "plaintext String parameter with a secret-like name",
			Expected:  "SecureString",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-339: Hardcoded credentials in resource config
// ---------------------------------------------------------------------------
//
// 339 fires in two cases:
//  1. A credential attribute holds a known non-empty literal (hardcoded).
//  2. A credential attribute references var.X / local.Y where the name
//     looks secret-like (taint tracking, one hop). The value could not be
//     resolved statically, so the name is the signal: an unresolved
//     var.db_password flowing into a password attribute is reported with
//     the taint path as evidence. Clean names and unknown shapes stay
//     silent. Only one level of indirection (ref -> attribute) is traced.

type hardcodedCredentials struct{}

func (hardcodedCredentials) ID() string { return "AEGIS-AWS-339" }
func (hardcodedCredentials) Title() string {
	return "Hardcoded credentials in resource config"
}
func (hardcodedCredentials) Description() string {
	return "A database password written as a literal in Terraform config is " +
		"stored in state, plan output, and version control. The same holds " +
		"for a secret-like variable or local flowing into a credential " +
		"attribute. Reference a secrets manager or a generated password " +
		"instead. The secret value is never included in findings."
}
func (hardcodedCredentials) Severity() ir.Severity { return ir.SeverityHigh }

func (hardcodedCredentials) AppliesTo(resType string) bool {
	return resType == "aws_db_instance" ||
		resType == "aws_rds_cluster" ||
		resType == "aws_redshift_cluster" ||
		resType == "aws_docdb_cluster" ||
		resType == "aws_neptune_cluster" ||
		resType == "aws_fsx_ontap_file_system"
}

// credentialAttr returns the password attribute name for the resource type.
func credentialAttr(resType string) string {
	switch resType {
	case "aws_redshift_cluster":
		return "master_password"
	case "aws_fsx_ontap_file_system":
		return "fsx_admin_password"
	default:
		return "password"
	}
}

func (hardcodedCredentials) Check(r ir.Resource) []ir.Finding {
	attr := credentialAttr(r.Type)
	pw, span, present, known := getString(r, attr)
	if !present || !known || strings.TrimSpace(pw) == "" {
		return nil // absent, unresolved, or empty: nothing hardcoded
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-339",
		Title:       (hardcodedCredentials{}).Title(),
		Description: (hardcodedCredentials{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(span, r.Span),
			Actual:    "[REDACTED]",
			Expected:  "reference to a secrets manager or generated password",
		},
	}}
}

// CheckAll adds taint tracking: a credential attribute holding an
// unresolved var.X / local.Y reference whose name looks secret-like is
// reported with the taint path as evidence. Literal findings come from
// Check; taint findings are appended. Results are sorted for determinism.
func (hardcodedCredentials) CheckAll(resources []ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, r := range resources {
		if !(hardcodedCredentials{}).AppliesTo(r.Type) {
			continue
		}
		out = append(out, (hardcodedCredentials{}).Check(r)...)
		if f := checkCredentialTaint(r, resources); f != nil {
			out = append(out, *f)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Resource != out[j].Resource {
			return out[i].Resource < out[j].Resource
		}
		return out[i].Evidence.Actual < out[j].Evidence.Actual
	})
	return out
}

var _ ir.CrossResourceRule = hardcodedCredentials{}

// checkCredentialTaint reports a 339 finding when a credential attribute
// holds an unresolved var/local reference with a secret-like name.
// One level of indirection only: ref -> attribute. Anything else (known
// literals, non-secret names, unknown shapes) yields nil.
// Variables declared with sensitive = true are skipped: the author followed
// best practice by marking the value sensitive, so flagging it as
// "hardcoded" would be a false positive.
func checkCredentialTaint(r ir.Resource, resources []ir.Resource) *ir.Finding {
	attr := credentialAttr(r.Type)
	v, ok := r.Attributes[attr]
	if !ok || !v.IsRef() {
		return nil // not a reference: literal case handled by Check
	}
	head, name, ok := splitTaintRef(v.Ref)
	if !ok || (head != "var" && head != "local") {
		return nil
	}
	if !secretLikeName(name) {
		return nil // clean name: cannot call it a secret
	}
	if head == "var" && isSensitiveVariable(name, resources) {
		return nil // sensitive = true: best practice followed, not hardcoded
	}
	taintPath := v.Ref + " -> " + r.Address() + "." + attr
	return &ir.Finding{
		RuleID:      "AEGIS-AWS-339",
		Title:       (hardcodedCredentials{}).Title(),
		Description: (hardcodedCredentials{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(v.Span, r.Span),
			Actual:    "[REDACTED via " + taintPath + "]",
			Expected:  "reference to a secrets manager or generated password",
		},
	}
}

// isSensitiveVariable reports whether the named variable is declared with
// sensitive = true, by looking up the synthetic terraform_variable resource.
func isSensitiveVariable(name string, resources []ir.Resource) bool {
	for _, res := range resources {
		if res.Type != "terraform_variable" || res.Name != name {
			continue
		}
		if s, ok := res.Attributes["sensitive"]; ok {
			if b, ok := s.AsBool(); ok && b {
				return true
			}
		}
	}
	return false
}

// splitTaintRef splits "var.db_password" into ("var", "db_password").
// Index suffixes ("var.list[0]") are stripped from the name.
func splitTaintRef(ref string) (head, name string, ok bool) {
	i := strings.Index(ref, ".")
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	head, rest := ref[:i], ref[i+1:]
	if j := strings.Index(rest, "["); j >= 0 {
		rest = rest[:j]
	}
	// Only the first path segment is the variable/local name.
	if j := strings.Index(rest, "."); j >= 0 {
		rest = rest[:j]
	}
	if rest == "" {
		return "", "", false
	}
	return head, rest, true
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-340: CloudTrail without global service events
// ---------------------------------------------------------------------------

type cloudtrailNoGlobalEvents struct{}

func (cloudtrailNoGlobalEvents) ID() string { return "AEGIS-AWS-340" }
func (cloudtrailNoGlobalEvents) Title() string {
	return "CloudTrail without global service events"
}
func (cloudtrailNoGlobalEvents) Description() string {
	return "With include_global_service_events disabled, the trail misses " +
		"IAM, STS, and other global-service API calls. The provider default " +
		"is true, so only an explicit false is a finding."
}
func (cloudtrailNoGlobalEvents) Severity() ir.Severity { return ir.SeverityMedium }

func (cloudtrailNoGlobalEvents) AppliesTo(resType string) bool {
	return resType == "aws_cloudtrail"
}

func (cloudtrailNoGlobalEvents) Check(r ir.Resource) []ir.Finding {
	global, span, present, known := getBool(r, "include_global_service_events")
	if !present || !known {
		return nil // provider default is true; unresolved: cannot decide
	}
	if !global {
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-340",
			Title:       (cloudtrailNoGlobalEvents{}).Title(),
			Description: (cloudtrailNoGlobalEvents{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "include_global_service_events",
				Span:      evidenceSpan(span, r.Span),
				Actual:    "false",
				Expected:  "true",
			},
		}}
	}
	return nil
}
