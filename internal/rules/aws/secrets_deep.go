package aws

import (
	"encoding/base64"
	"regexp"
	"sort"
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// Deep secrets detection (AEGIS-AWS-534–539)
//
// Expands secret detection to places Checkov doesn't look: EC2 user_data,
// provisioner connections, Terraform outputs, resource tags, variable
// defaults, and local values.
//
// CONTRACT (all six rules):
//   - Secret VALUES never appear in findings. Evidence.Actual is always
//     "[REDACTED]" or "[REDACTED via ...]" with a location hint, never
//     the secret itself.
//   - Unknown/unresolved values never fire.
//   - No panics: all type assertions are defensive.
//   - Deterministic: findings sorted by resource, then rule ID.
// ---------------------------------------------------------------------------

// DeepSecretsRules returns the deep-secret rules in ID order (534-539).
func DeepSecretsRules() []ir.Rule {
	return []ir.Rule{
		userDataSecret{},        // AEGIS-AWS-534
		provisionerSecret{},     // AEGIS-AWS-535
		outputSecret{},          // AEGIS-AWS-536
		tagSecret{},             // AEGIS-AWS-537
		variableDefaultSecret{}, // AEGIS-AWS-538
		localSecret{},           // AEGIS-AWS-539
	}
}

// awsKeyPattern matches AWS access key IDs (AKIA...).
var awsKeyPattern = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)

// genericSecretPattern matches common secret assignments in scripts:
// password=..., passwd=..., secret=..., token=..., api_key=... followed
// by a non-empty value. Case-insensitive.
var genericSecretPattern = regexp.MustCompile(
	`(?i)(password|passwd|pwd|secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*["']?([^\s"'\\]{4,})`)

// containsSecret scans text for AWS keys or generic secret assignments.
// Returns a short, redacted description of what was found (never the value).
func containsSecret(text string) (string, bool) {
	if awsKeyPattern.MatchString(text) {
		return "AWS access key ID", true
	}
	if m := genericSecretPattern.FindStringSubmatch(text); m != nil {
		return m[1] + " assignment", true
	}
	return "", false
}

// decodeUserData returns the plaintext of user_data, decoding base64
// when the attribute is user_data_base64. Returns "" on decode failure.
func decodeUserData(attr string, v ir.Value) string {
	s, ok := v.AsString()
	if !ok || strings.TrimSpace(s) == "" {
		return ""
	}
	if attr == "user_data_base64" {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
		if err != nil {
			// Try raw URL encoding as fallback.
			decoded, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
			if err != nil {
				return ""
			}
		}
		return string(decoded)
	}
	return s
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-534: Secrets in EC2 user_data
// ---------------------------------------------------------------------------

type userDataSecret struct{}

func (userDataSecret) ID() string { return "AEGIS-AWS-534" }
func (userDataSecret) Title() string {
	return "Secrets in EC2 user_data"
}
func (userDataSecret) Description() string {
	return "A secret (AWS key, password, token) embedded in EC2 user_data " +
		"is visible in the console, API responses, and instance metadata. " +
		"user_data_base64 is decoded before scanning. Pass secrets via " +
		"instance profiles, SSM Parameter Store, or Secrets Manager instead. " +
		"The secret value is never included in findings."
}
func (userDataSecret) Severity() ir.Severity { return ir.SeverityCritical }

func (userDataSecret) AppliesTo(resType string) bool {
	switch resType {
	case "aws_instance",
		"aws_launch_template",
		"aws_launch_configuration",
		"aws_spot_instance_request",
		"aws_autoscaling_group":
		return true
	}
	return false
}

func (userDataSecret) Check(r ir.Resource) []ir.Finding {
	for _, attr := range []string{"user_data", "user_data_base64"} {
		v, ok := r.Attributes[attr]
		if !ok {
			continue
		}
		text := decodeUserData(attr, v)
		if text == "" {
			continue // absent, unresolved, or undecodable: silent
		}
		if kind, found := containsSecret(text); found {
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-534",
				Title:       (userDataSecret{}).Title(),
				Description: (userDataSecret{}).Description(),
				Severity:    ir.SeverityCritical,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: attr,
					Span:      evidenceSpan(v.Span, r.Span),
					Actual:    "[REDACTED: " + kind + " in " + attr + "]",
					Expected:  "no secrets in user_data; use instance profiles or SSM/Secrets Manager",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-535: Secrets in provisioner connections
// ---------------------------------------------------------------------------

type provisionerSecret struct{}

func (provisionerSecret) ID() string { return "AEGIS-AWS-535" }
func (provisionerSecret) Title() string {
	return "Plaintext password in provisioner connection"
}
func (provisionerSecret) Description() string {
	return "A provisioner connection block with a hardcoded password " +
		"stores credentials in Terraform state and version control. " +
		"Use SSH keys, bastion hosts, or a secrets manager instead. " +
		"The secret value is never included in findings."
}
func (provisionerSecret) Severity() ir.Severity { return ir.SeverityHigh }

func (provisionerSecret) AppliesTo(resType string) bool {
	// Provisioners can appear on any resource; check broadly but only
	// fire when a provisioner block with a connection password exists.
	return strings.HasPrefix(resType, "aws_")
}

func (provisionerSecret) Check(r ir.Resource) []ir.Finding {
	blocks := blockList(r.Attributes, "provisioner")
	for _, pb := range blocks {
		connBlocks := blockList(pb, "connection")
		for _, cb := range connBlocks {
			pwVal, ok := cb["password"]
			if !ok {
				continue
			}
			pw, ok := pwVal.AsString()
			if !ok || strings.TrimSpace(pw) == "" {
				continue // unresolved or empty: silent
			}
			// A non-empty literal password in a connection block is
			// always a hardcoded credential.
			return []ir.Finding{{
				RuleID:      "AEGIS-AWS-535",
				Title:       (provisionerSecret{}).Title(),
				Description: (provisionerSecret{}).Description(),
				Severity:    ir.SeverityHigh,
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: "provisioner.connection.password",
					Span:      evidenceSpan(pwVal.Span, r.Span),
					Actual:    "[REDACTED]",
					Expected:  "SSH key authentication or secrets manager reference",
				},
			}}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-536: Secrets in Terraform outputs
// ---------------------------------------------------------------------------

type outputSecret struct{}

func (outputSecret) ID() string { return "AEGIS-AWS-536" }
func (outputSecret) Title() string {
	return "Sensitive value exposed in Terraform output"
}
func (outputSecret) Description() string {
	return "A Terraform output with a secret-like name (password, secret, " +
		"key, token) that is not marked sensitive exposes the value in " +
		"CLI output, state files, and CI logs. Set sensitive = true. " +
		"The secret value is never included in findings."
}
func (outputSecret) Severity() ir.Severity { return ir.SeverityHigh }

func (outputSecret) AppliesTo(resType string) bool {
	return resType == "terraform_output"
}

func (outputSecret) Check(r ir.Resource) []ir.Finding {
	if !secretLikeName(r.Name) {
		return nil // name doesn't suggest a secret: silent
	}
	sens, _, present, known := getBool(r, "sensitive")
	if present && known && sens {
		return nil // explicitly marked sensitive: compliant
	}
	// sensitive absent, false, or unresolved: the output exposes the value.
	val, ok := r.Attributes["value"]
	span := r.Span
	if ok {
		span = evidenceSpan(val.Span, r.Span)
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-536",
		Title:       (outputSecret{}).Title(),
		Description: (outputSecret{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "sensitive",
			Span:      span,
			Actual:    "[REDACTED: output '" + r.Name + "' exposes a secret-like value]",
			Expected:  "sensitive = true",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-537: Secrets in resource tags
// ---------------------------------------------------------------------------

type tagSecret struct{}

func (tagSecret) ID() string { return "AEGIS-AWS-537" }
func (tagSecret) Title() string {
	return "Secret stored in resource tags"
}
func (tagSecret) Description() string {
	return "A resource tag with a secret-like key (password, secret, token) " +
		"and a non-empty value exposes credentials in the console, APIs, " +
		"and cost reports. Tags are not a secrets store. " +
		"The secret value is never included in findings."
}
func (tagSecret) Severity() ir.Severity { return ir.SeverityMedium }

func (tagSecret) AppliesTo(resType string) bool {
	return strings.HasPrefix(resType, "aws_")
}

func (tagSecret) Check(r ir.Resource) []ir.Finding {
	tagsVal, ok := r.Attributes["tags"]
	if !ok {
		return nil
	}
	tags, ok := tagsVal.AsMap()
	if !ok {
		return nil // unresolved or non-map: silent
	}
	// Sort keys for determinism.
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !secretLikeName(k) {
			continue
		}
		v := tags[k]
		s, ok := v.AsString()
		if !ok || strings.TrimSpace(s) == "" {
			continue // unresolved or empty: silent
		}
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-537",
			Title:       (tagSecret{}).Title(),
			Description: (tagSecret{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "tags." + k,
				Span:      evidenceSpan(v.Span, r.Span),
				Actual:    "[REDACTED: secret-like tag '" + k + "']",
				Expected:  "no secrets in tags; use a secrets manager",
			},
		}}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-538: Database password in plaintext variable default
// ---------------------------------------------------------------------------

type variableDefaultSecret struct{}

func (variableDefaultSecret) ID() string { return "AEGIS-AWS-538" }
func (variableDefaultSecret) Title() string {
	return "Secret in plaintext variable default"
}
func (variableDefaultSecret) Description() string {
	return "A Terraform variable with a secret-like name (password, secret, " +
		"token) and a hardcoded plaintext default bakes the credential into " +
		"version control. Leave the default empty and inject via a secrets " +
		"manager, vault provider, or CI secret. " +
		"The secret value is never included in findings."
}
func (variableDefaultSecret) Severity() ir.Severity { return ir.SeverityHigh }

func (variableDefaultSecret) AppliesTo(resType string) bool {
	return resType == "terraform_variable"
}

func (variableDefaultSecret) Check(r ir.Resource) []ir.Finding {
	if !secretLikeName(r.Name) {
		return nil
	}
	defVal, ok := r.Attributes["default"]
	if !ok {
		return nil
	}
	def, ok := defVal.AsString()
	if !ok || strings.TrimSpace(def) == "" {
		return nil // unresolved or empty default: silent
	}
	// Skip values that look like vault/secret-manager references.
	lower := strings.ToLower(def)
	for _, safe := range []string{"vault", "secretsmanager", "ssm", "keyvault", "var.", "local."} {
		if strings.Contains(lower, safe) {
			return nil
		}
	}
	return []ir.Finding{{
		RuleID:      "AEGIS-AWS-538",
		Title:       (variableDefaultSecret{}).Title(),
		Description: (variableDefaultSecret{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "default",
			Span:      evidenceSpan(defVal.Span, r.Span),
			Actual:    "[REDACTED: plaintext default for secret-like variable '" + r.Name + "']",
			Expected:  "empty default; inject via secrets manager or CI secret",
		},
	}}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-539: Secrets in local values
// ---------------------------------------------------------------------------

type localSecret struct{}

func (localSecret) ID() string { return "AEGIS-AWS-539" }
func (localSecret) Title() string {
	return "Secret in hardcoded local value"
}
func (localSecret) Description() string {
	return "A Terraform local with a secret-like name (password, secret, " +
		"token) and a hardcoded string value bakes the credential into " +
		"version control and state. Reference a secrets manager instead. " +
		"The secret value is never included in findings."
}
func (localSecret) Severity() ir.Severity { return ir.SeverityMedium }

func (localSecret) AppliesTo(resType string) bool {
	return resType == "terraform_locals"
}

func (localSecret) Check(r ir.Resource) []ir.Finding {
	// Sort attribute names for determinism.
	names := make([]string, 0, len(r.Attributes))
	for n := range r.Attributes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if !secretLikeName(n) {
			continue
		}
		v := r.Attributes[n]
		s, ok := v.AsString()
		if !ok || strings.TrimSpace(s) == "" {
			continue // unresolved or empty: silent
		}
		// Skip references to other vars/locals or secret managers.
		lower := strings.ToLower(s)
		for _, safe := range []string{"vault", "secretsmanager", "ssm", "keyvault"} {
			if strings.Contains(lower, safe) {
				continue
			}
		}
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-539",
			Title:       (localSecret{}).Title(),
			Description: (localSecret{}).Description(),
			Severity:    ir.SeverityMedium,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: n,
				Span:      evidenceSpan(v.Span, r.Span),
				Actual:    "[REDACTED: hardcoded secret in local '" + n + "']",
				Expected:  "reference to a secrets manager",
			},
		}}
	}
	return nil
}
