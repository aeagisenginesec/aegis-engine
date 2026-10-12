package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"aegis/internal/ir"
)

func sampleResult() ir.ScanResult {
	return ir.ScanResult{
		Target:    "/tmp/proj",
		Resources: 3,
		Findings: []ir.Finding{
			{
				RuleID:      "aws-s3-public-acl",
				Title:       "S3 bucket has public ACL",
				Description: "The bucket ACL allows public read access.",
				Severity:    ir.SeverityHigh,
				Resource:    "aws_s3_bucket.data",
				Evidence: ir.Evidence{
					Attribute: "acl",
					Span:      ir.Span{File: "main.tf", StartLine: 12, StartCol: 3, EndLine: 12, EndCol: 20},
					Actual:    "public-read",
					Expected:  "private",
				},
			},
			{
				RuleID:      "aws-db-master-password",
				Title:       "Database master password in plaintext",
				Description: "Master password is hardcoded.",
				Severity:    ir.SeverityCritical,
				Resource:    "aws_db_instance.main",
				Evidence: ir.Evidence{
					Attribute: "master_password",
					Span:      ir.Span{File: "db.tf", StartLine: 7, StartCol: 3},
					Actual:    "Sup3rSecret123!",
					Expected:  "reference a secrets manager",
				},
			},
		},
		Diagnostics: []ir.Diagnostic{
			{Level: "warning", Message: "unparsed block", Span: ir.Span{File: "odd.tf"}},
		},
	}
}

func TestWriteJSONEnvelope(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(buf.Bytes(), &env); err != nil {
		t.Fatalf("JSON output does not parse: %v", err)
	}
	if env["aegis_version"] != Version {
		t.Errorf("missing/wrong aegis_version: %v", env["aegis_version"])
	}
	if env["target"] != "/tmp/proj" {
		t.Errorf("wrong target: %v", env["target"])
	}
	if env["resources_scanned"] != float64(3) {
		t.Errorf("wrong resources_scanned: %v", env["resources_scanned"])
	}
	findings, ok := env["findings"].([]any)
	if !ok || len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %v", env["findings"])
	}
	// Secret redaction must fire in JSON output.
	second := findings[1].(map[string]any)
	ev := second["evidence"].(map[string]any)
	if ev["actual"] != "[REDACTED]" {
		t.Errorf("secret not redacted in JSON: %v", ev["actual"])
	}
	first := findings[0].(map[string]any)
	if first["evidence"].(map[string]any)["actual"] != "public-read" {
		t.Errorf("non-secret value wrongly redacted")
	}
}

func TestWriteSARIFValid(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	var log map[string]any
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("SARIF output does not parse as JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("wrong SARIF version: %v", log["version"])
	}
	runs := log["runs"].([]any)
	if len(runs) != 1 {
		t.Fatalf("expected exactly 1 run, got %d", len(runs))
	}
	run := runs[0].(map[string]any)
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "aegis" {
		t.Errorf("wrong tool name: %v", driver["name"])
	}
	rules := driver["rules"].([]any)
	if len(rules) != 2 {
		t.Errorf("expected 2 rules derived from findings, got %d", len(rules))
	}
	results := run["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	r0 := results[0].(map[string]any)
	if r0["ruleId"] != "aws-s3-public-acl" {
		t.Errorf("wrong ruleId: %v", r0["ruleId"])
	}
	if r0["level"] != "error" { // high -> error
		t.Errorf("wrong level mapping for high: %v", r0["level"])
	}
	loc := r0["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	if loc["artifactLocation"].(map[string]any)["uri"] != "main.tf" {
		t.Errorf("wrong artifact uri: %v", loc["artifactLocation"])
	}
	region := loc["region"].(map[string]any)
	if region["startLine"] != float64(12) || region["startColumn"] != float64(3) {
		t.Errorf("wrong region mapping: %v", region)
	}
	// Secret redaction fires in SARIF messages/evidence too (evidence isn't in
	// SARIF results, but the redacted copy must not leak via rules either).
	if strings.Contains(buf.String(), "Sup3rSecret123!") {
		t.Errorf("secret leaked into SARIF output")
	}
}

func TestWriteSARIFLevels(t *testing.T) {
	res := ir.ScanResult{Target: "t", Findings: []ir.Finding{}}
	for sev, want := range map[ir.Severity]string{
		ir.SeverityCritical: "error",
		ir.SeverityHigh:     "error",
		ir.SeverityMedium:   "warning",
		ir.SeverityLow:      "note",
		ir.SeverityInfo:     "note",
	} {
		res.Findings = []ir.Finding{{
			RuleID:   "r-" + string(sev),
			Title:    "t",
			Severity: sev,
			Evidence: ir.Evidence{Span: ir.Span{File: "f.tf", StartLine: 1, StartCol: 1}},
		}}
		var buf bytes.Buffer
		if err := WriteSARIF(&buf, res); err != nil {
			t.Fatal(err)
		}
		var log map[string]any
		_ = json.Unmarshal(buf.Bytes(), &log)
		got := log["runs"].([]any)[0].(map[string]any)["results"].([]any)[0].(map[string]any)["level"]
		if got != want {
			t.Errorf("severity %s: got level %v, want %v", sev, got, want)
		}
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteText(&buf, sampleResult()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "HIGH aws-s3-public-acl main.tf:12 — S3 bucket has public ACL") {
		t.Errorf("missing expected finding line:\n%s", out)
	}
	if !strings.Contains(out, `evidence: acl = "public-read"`) {
		t.Errorf("missing evidence line:\n%s", out)
	}
	if strings.Contains(out, "Sup3rSecret123!") {
		t.Errorf("secret leaked into text output")
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("expected redacted marker in text output")
	}
}
