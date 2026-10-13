// Package azure — legacy SQL server coverage (AEGIS-AZURE-314).
//
// The legacy azurerm_sql_server resource previously had no auditing,
// password, or firewall coverage: the mssql_server rules (AZURE-008/009,
// 025, 207) do not apply to it, and the provider exposes no TLS control
// on the legacy type (TLS is platform-enforced for Azure SQL Database,
// so there is no legacy TLS attribute to check — documented, not
// silently skipped). This file closes the legacy gap:
//
//   - 314: weak administrator password on SQL/MySQL/PostgreSQL servers.
//   - 009 extended: auditing now covers azurerm_sql_server as well as
//     azurerm_mssql_server (see azure2.go).
//
// Absent-attribute policy: the password rule fires only on a present,
// known, weak password (never on absent/unknown — a password from a
// variable or secret reference cannot be judged). Findings NEVER carry
// the password value: evidence Actual is a fixed redacted string.
package azure

import (
	"regexp"
	"strings"

	"aegis/internal/ir"
)

// Azure22Rules returns legacy SQL server rules in ID order.
func Azure22Rules() []ir.Rule {
	return []ir.Rule{
		sqlWeakAdminPassword{}, // AEGIS-AZURE-314
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-314: SQL server administrator with weak password
// ---------------------------------------------------------------------------

type sqlWeakAdminPassword struct{}

func (sqlWeakAdminPassword) ID() string { return "AEGIS-AZURE-314" }
func (sqlWeakAdminPassword) Title() string {
	return "SQL server administrator with weak password"
}
func (sqlWeakAdminPassword) Description() string {
	return "A database administrator password from a well-known weak list, " +
		"shorter than 10 characters, or a single dictionary word plus " +
		"digits, is guessable by online brute force. Use a long " +
		"randomly generated password stored in Key Vault (never a " +
		"literal in configuration). The password value is never shown " +
		"in findings."
}
func (sqlWeakAdminPassword) Severity() ir.Severity { return ir.SeverityHigh }

func (sqlWeakAdminPassword) AppliesTo(resType string) bool {
	switch resType {
	case "azurerm_sql_server",
		"azurerm_mssql_server",
		"azurerm_mysql_server",
		"azurerm_postgresql_server",
		"azurerm_mysql_flexible_server",
		"azurerm_postgresql_flexible_server":
		return true
	}
	return false
}

func (s sqlWeakAdminPassword) Check(r ir.Resource) []ir.Finding {
	pw, span, present, known := getString(r, "administrator_login_password")
	if !present || !known {
		return nil // absent or unresolved: cannot decide
	}
	if !isWeakPassword(pw) {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "administrator_login_password", span,
		"weak password [REDACTED]",
		"long randomly generated password (Key Vault / secret reference)")}
}

// weakPasswords are well-known passwords seen in breaches and default
// credential lists, matched case-insensitively, with common leet and
// trailing-digit variants.
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
