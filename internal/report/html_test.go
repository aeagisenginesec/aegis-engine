package report

import (
	"bytes"
	"strings"
	"testing"

	"aegis/internal/ir"
)

func TestWriteHTMLAttestation(t *testing.T) {
	res := ir.ScanResult{
		Target:    "demo",
		Resources: 3,
		Findings: []ir.Finding{{
			RuleID:   "AEGIS-AWS-001",
			Title:    "S3 bucket <script>alert(1)</script> not encrypted",
			Severity: ir.SeverityHigh,
			Resource: "aws_s3_bucket.uploads",
			Evidence: ir.Evidence{
				Attribute: "password",
				Actual:    "hunter2-secret",
				Span:      ir.Span{File: "main.tf", StartLine: 4},
			},
			Compliance: []ir.ComplianceRef{{Framework: "NIST-800-53", Control: "SC-28"}},
		}},
		ComplianceSummaries: []*ir.ComplianceSummary{{
			Framework:       "NIST-800-53",
			ControlsTotal:   10,
			ControlsPassing: 9,
			ControlsFailing: 1,
			FailedControls:  []string{"SC-28"},
		}},
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, res); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"<!DOCTYPE html>", "Compliance posture", "NIST-800-53",
		"AEGIS-AWS-001", "main.tf:4", "SC-28",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("attestation should contain %q", want)
		}
	}
	// User-controlled strings are escaped, never raw markup.
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("finding title was not HTML-escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected escaped title in output")
	}
	// Secrets never reach the page.
	if strings.Contains(out, "hunter2-secret") {
		t.Error("secret evidence value leaked into the attestation")
	}
	// Deterministic: a second render is byte-identical.
	var buf2 bytes.Buffer
	if err := WriteHTML(&buf2, res); err != nil {
		t.Fatalf("WriteHTML (2nd): %v", err)
	}
	if buf.String() != buf2.String() {
		t.Error("attestation output is not deterministic")
	}
}

func TestWriteHTMLEmptyScan(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, ir.ScanResult{Target: "clean"}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	if !strings.Contains(buf.String(), "No findings.") {
		t.Errorf("empty scan should say so, got:\n%s", buf.String())
	}
}
