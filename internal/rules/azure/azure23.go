// Package azure — Phase B gap rules (AEGIS-AZURE-315..316).
//
//   - 315: MySQL flexible server with public network access enabled —
//     the MySQL counterpart of AEGIS-AZURE-169 (PostgreSQL). The ARM
//     adapter promotes nested network.publicNetworkAccess to the flat
//     public_network_access_enabled attribute for both flexible-server
//     types; this rule reuses the publicNetOpen helper.
//   - 316: SecureString/secureObject parameter (ARM template or Bicep
//     @secure() param) with a hardcoded default — the ARM/Bicep
//     counterpart of AEGIS-AWS-857 (CFN parameter secrets). The ARM
//     adapter emits arm_parameter resources for parameters with known
//     defaults; this rule mirrors AWS-857's logic: fire when the type
//     is secureString/secureObject (or the name is secret-like) AND the
//     default is a non-empty literal, skipping placeholder defaults and
//     secret-reference values. The secret value is never shown in
//     findings.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure23Rules returns the Phase B Azure rules in ID order.
func Azure23Rules() []ir.Rule {
	return []ir.Rule{
		mysqlFlexPublicNet{}, // AEGIS-AZURE-315
		armParameterSecret{}, // AEGIS-AZURE-316
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-315: MySQL flexible server with public network access enabled
// ---------------------------------------------------------------------------

type mysqlFlexPublicNet struct{}

func (mysqlFlexPublicNet) ID() string { return "AEGIS-AZURE-315" }
func (mysqlFlexPublicNet) Title() string {
	return "MySQL flexible server with public network access enabled"
}
func (mysqlFlexPublicNet) Description() string {
	return "azurerm_mysql_flexible_server with " +
		"public_network_access_enabled (the provider default) exposes the " +
		"database to the internet. Disable public network access and use " +
		"VNet integration or private endpoints."
}
func (mysqlFlexPublicNet) Severity() ir.Severity { return ir.SeverityHigh }

func (mysqlFlexPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_mysql_flexible_server"
}

func (mysqlFlexPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(mysqlFlexPublicNet{}, r, "public_network_access_enabled", "azurerm_mysql_flexible_server")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-316: SecureString parameter with hardcoded default value
// ---------------------------------------------------------------------------

type armParameterSecret struct{}

func (armParameterSecret) ID() string { return "AEGIS-AZURE-316" }
func (armParameterSecret) Title() string {
	return "SecureString parameter should not have hardcoded default value"
}
func (armParameterSecret) Description() string {
	return "An ARM/Bicep parameter of type secureString (or secureObject), " +
		"or with a secret-like name, carrying a hardcoded plaintext " +
		"default bakes the credential into version control. Leave the " +
		"default empty and inject via Key Vault or a CI secret. The " +
		"secret value is never included in findings."
}
func (armParameterSecret) Severity() ir.Severity { return ir.SeverityHigh }

func (armParameterSecret) AppliesTo(resType string) bool {
	return resType == "arm_parameter"
}

// armParamSecretLikeName reports whether a parameter name suggests a
// secret. Mirrors the AWS cfn_parameter check's hints.
func armParamSecretLikeName(name string) bool {
	lower := strings.ToLower(name)
	for _, hint := range []string{
		"password", "passwd", "secret", "token", "apikey", "api_key",
		"private_key", "credential",
	} {
		if strings.Contains(lower, hint) {
			return true
		}
	}
	return false
}

func (armParameterSecret) Check(r ir.Resource) []ir.Finding {
	rule := armParameterSecret{}
	typ, _, tpresent, tknown := getString(r, "type")
	secureType := tpresent && tknown &&
		(strings.EqualFold(strings.TrimSpace(typ), "secureString") ||
			strings.EqualFold(strings.TrimSpace(typ), "secureObject"))
	if !secureType && !armParamSecretLikeName(r.Name) {
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
	// Skip values that look like secret-manager / Key Vault references.
	lower := strings.ToLower(def)
	for _, safe := range []string{"vault", "keyvault", "secretsmanager", "ssm", "resolve", "arn:"} {
		if strings.Contains(lower, safe) {
			return nil
		}
	}
	// Skip obvious placeholder defaults.
	switch lower {
	case "changeme", "change_me", "example", "test", "xxx", "xxxx", "dummy", "placeholder":
		return nil
	}
	return []ir.Finding{{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: "default",
			Span:      evidenceSpan(defVal.Span, r.Span),
			Actual:    "[REDACTED: plaintext default for secret-like parameter '" + r.Name + "']",
			Expected:  "empty default; inject via Key Vault or CI secret",
		},
	}}
}
