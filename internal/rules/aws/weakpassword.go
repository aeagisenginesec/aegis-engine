// Package aws — weak database password detection (AEGIS-AWS-850).
//
// Round-3 evaluation gap: RDS instances with the weak default master
// password "password123" produced no finding. This rule judges literal
// master passwords on database resources with the same guessability
// heuristic as AEGIS-AZURE-314 (well-known weak list, length and
// character-class floors, word-plus-digits shape). Passwords from
// variables, secrets managers, or references are Unknown and stay
// quiet: only a literal weak password is evidence. Findings NEVER carry
// the password value.
package aws

import (
	"regexp"
	"strings"

	"aegis/internal/ir"
)

// WeakPasswordRules returns weak-password rules in ID order.
func WeakPasswordRules() []ir.Rule {
	return []ir.Rule{
		dbWeakPassword{}, // AEGIS-AWS-850
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-850: Database instance with weak password
// ---------------------------------------------------------------------------

type dbWeakPassword struct{}

func (dbWeakPassword) ID() string { return "AEGIS-AWS-850" }
func (dbWeakPassword) Title() string {
	return "Database instance with weak password"
}
func (dbWeakPassword) Description() string {
	return "A database master password from a well-known weak list, " +
		"shorter than 10 characters, or a single dictionary word plus " +
		"digits, is guessable by online brute force. Use a long " +
		"randomly generated password (Secrets Manager / secret " +
		"reference, never a literal in configuration). The password " +
		"value is never shown in findings."
}
func (dbWeakPassword) Severity() ir.Severity { return ir.SeverityHigh }

// dbPasswordAttrs maps each database resource type to the password
// attribute names it may carry. CloudFormation Redshift arrives as
// master_user_password (generic snake_case); Terraform uses
// master_password.
var dbPasswordAttrs = map[string][]string{
	"aws_db_instance":      {"password"},
	"aws_rds_cluster":      {"master_password"},
	"aws_redshift_cluster": {"master_password", "master_user_password"},
	"aws_docdb_cluster":    {"master_password"},
	"aws_neptune_cluster":  {"master_password"},
}

func (dbWeakPassword) AppliesTo(resType string) bool {
	_, ok := dbPasswordAttrs[resType]
	return ok
}

func (s dbWeakPassword) Check(r ir.Resource) []ir.Finding {
	for _, attr := range dbPasswordAttrs[r.Type] {
		pw, span, present, known := getString(r, attr)
		if !present || !known {
			continue // absent or unresolved: cannot decide
		}
		if !isWeakPassword(pw) {
			return nil
		}
		return []ir.Finding{{
			RuleID:      "AEGIS-AWS-850",
			Title:       (dbWeakPassword{}).Title(),
			Description: (dbWeakPassword{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: attr,
				Span:      evidenceSpan(span, r.Span),
				Actual:    "weak password [REDACTED]",
				Expected:  "long randomly generated password (Secrets Manager / secret reference)",
			},
		}}
	}
	return nil
}

// weakPasswords are well-known passwords seen in breaches and default
// credential lists, matched case-insensitively, with common leet and
// trailing-digit variants. Kept in sync with the Azure pack's copy
// (AEGIS-AZURE-314); both packages duplicate small helpers by design.
var weakPasswords = map[string]bool{
	"password": true, "password1": true, "password123": true,
	"password123!": true, "password1234": true, "password!": true,
	"passw0rd": true, "passw0rd123": true, "p@ssw0rd": true,
	"p@ssword": true, "p@ssword123": true, "p@ssw0rd123": true,
	"admin": true, "admin123": true, "admin1234": true,
	"admin123!": true, "administrator": true, "administrator123": true,
	"changeme": true, "changeme123": true, "change_me": true,
	"letmein": true, "letmein123": true, "welcome": true,
	"welcome123": true, "welcome1": true, "qwerty": true,
	"qwerty123": true, "123456": true, "12345678": true,
	"123456789": true, "1234567890": true, "1234567": true,
	"iloveyou": true, "monkey": true, "dragon": true,
	"master": true, "master123": true, "sunshine": true,
	"football": true, "test123": true, "test1234": true,
	"root123": true, "root1234": true, "sql123": true,
	"sql1234": true, "azure123": true, "azure1234": true,
	"microsoft123": true, "sa123456": true, "db123456": true,
	"database123": true, "server123": true,
}

// wordPlusDigits matches a single alphabetic word followed by digits and
// an optional trailing symbol: Password123!, Admin2024, Welcome1.
// Multi-segment passwords (Str0ng-4c2865-Db!) and interleaved
// alphanumeric passwords do not match.
var wordPlusDigits = regexp.MustCompile(`^[A-Za-z]{3,}[0-9]{1,6}[!@#$%^&*]?$`)

// isWeakPassword reports whether a literal password is guessable. An
// empty password is weak. Passwords of 10+ characters with at least 3
// of the 4 character classes and no word-plus-digits shape pass; this
// is a guessability heuristic, not a proof of strength.
func isWeakPassword(pw string) bool {
	if pw == "" {
		return true
	}
	if weakPasswords[strings.ToLower(pw)] {
		return true
	}
	if len(pw) < 10 {
		return true
	}
	classes := 0
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range pw {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	for _, b := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if b {
			classes++
		}
	}
	if len(pw) < 12 && classes < 3 {
		return true
	}
	if len(pw) < 16 && wordPlusDigits.MatchString(pw) {
		return true
	}
	return false
}
