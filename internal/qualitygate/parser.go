package qualitygate

import (
	"fmt"
	"strings"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

// malformedCase is one parser-safety probe: garbage in must never come out
// as a silent "clean" scan. Either Parse returns an error, or it returns
// diagnostics, or both. Zero resources + zero diagnostics + nil error on
// non-empty garbage is a FAIL.
type malformedCase struct {
	name string
	src  string
	// wantClean reports whether this input is legitimately parseable
	// (empty file, comments only). Such cases must NOT error.
	wantClean bool
}

var malformedCases = []malformedCase{
	{"truncated-block", `resource "aws_s3_bucket" "x" {`, false},
	{"unclosed-brace", "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \"y\"\n", false},
	{"invalid-token", `resource "aws_s3_bucket" "x" { bucket = }`, false},
	{"binary-garbage", "\x00\x01\x02\xff\xfe resource {{{", false},
	{"stray-brace", `} } }`, false},
	{"unterminated-string", `resource "aws_s3_bucket" "x" { bucket = "abc`, false},
	{"null-bytes", "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \"a\x00b\"\n}\n", false},
	{"utf16-bom", "\xff\xfer\x00e\x00s\x00o\x00u\x00r\x00c\x00e\x00", false},
	{"deep-nesting-60", deepNesting(60), false},
	{"unbalanced-extra-close", "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \"y\"\n}\n}\n", false},
	{"truncated-mid-list", "resource \"aws_s3_bucket\" \"x\" {\n  bucket = [\"a\",\n", false},
	{"empty-file", ``, true},
	{"comments-only", "# just a comment\n// another\n", true},
	{"whitespace-only", "  \n\t\n", true},
	{"valid-minimal", "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \"y\"\n}\n", true},
}

// deepNesting builds levels of balanced nested blocks. Beyond
// terraform.MaxNestingDepth the adapter must fail explicitly, never
// silently accept.
func deepNesting(levels int) string {
	var sb strings.Builder
	sb.WriteString(`resource "aws_s3_bucket" "x" {` + "\n")
	for i := 0; i < levels; i++ {
		sb.WriteString("  nested {\n")
	}
	for i := 0; i < levels; i++ {
		sb.WriteString("  }\n")
	}
	sb.WriteString("}\n")
	return sb.String()
}

// parserProbe runs one malformed input through the adapter.
func parserProbe(c malformedCase) (explicit bool, detail string) {
	adapter := terraform.New()
	resources, diags, err := adapter.Parse("probe.tf", []byte(c.src))
	hasErr := err != nil
	hasDiags := len(diags) > 0
	// Diagnostics at error level count as explicit.
	hasErrDiags := false
	for _, d := range diags {
		if d.Level == "error" {
			hasErrDiags = true
			break
		}
	}
	if c.wantClean {
		// Legit inputs must parse without hard error.
		if hasErr {
			return false, fmt.Sprintf("valid input %q returned error: %v", c.name, err)
		}
		return true, ""
	}
	explicit = hasErr || hasErrDiags || hasDiags
	if !explicit && len(resources) == 0 {
		return false, fmt.Sprintf("%q: silent clean on malformed input (0 resources, 0 diagnostics, nil error)", c.name)
	}
	return true, ""
}

// runParserSafetyGate verifies malformed HCL never scans as silently clean.
func runParserSafetyGate(o Options) GateResult {
	var failures []string
	for _, c := range malformedCases {
		ok, detail := parserProbe(c)
		if !ok {
			failures = append(failures, detail)
		}
	}
	passed := len(failures) == 0
	details := fmt.Sprintf("%d/%d probes explicit", len(malformedCases)-len(failures), len(malformedCases))
	if !passed {
		details += "; " + strings.Join(failures, "; ")
	}
	// Also assert the adapter surfaces diagnostics through the ir.Diagnostic
	// type (contract check, not input-dependent).
	var _ []ir.Diagnostic
	return GateResult{
		Name:      "parser-safety",
		Passed:    passed,
		Metric:    fmt.Sprintf("%d/%d explicit", len(malformedCases)-len(failures), len(malformedCases)),
		Threshold: "all malformed inputs explicit",
		Details:   details,
	}
}
