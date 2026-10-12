package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const vulnTF = `resource "aws_s3_bucket" "data" {
  acl = "public-read"
}
`

const cleanTF = `resource "null_resource" "ok" {
}
`

// writeFixtures creates a temp dir with one vulnerable and one clean .tf file.
func writeFixtures(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vuln.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clean.tf"), []byte(cleanTF), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestScanExitCodeFindings(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--format=json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	findings, ok := env["findings"].([]any)
	if !ok {
		t.Fatalf("no findings array in JSON output")
	}
	if len(findings) == 0 {
		t.Fatalf("expected findings for the vulnerable fixture, got none")
	}
	// The vulnerable bucket must trip the public-ACL rule; the real rule
	// pack also reports missing encryption/versioning — assert presence,
	// not an exact count, so the test tracks rule behavior, not pack size.
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.(map[string]any)["rule_id"].(string)] = true
	}
	if !seen["AEGIS-AWS-002"] {
		t.Errorf("expected rule AEGIS-AWS-002 among findings, got %v", seen)
	}
	if env["aegis_version"] != "1.0.0" {
		t.Errorf("missing aegis_version in envelope")
	}
}

func TestScanCleanExitCode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clean.tf"), []byte(cleanTF), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 (clean), got %d; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "findings: 0") {
		t.Errorf("expected clean text summary, got:\n%s", stdout.String())
	}
}

func TestScanUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"scan"},
		{"frobnicate", "x"},
		{"scan", t.TempDir(), "--format=yaml"},
		{"scan", t.TempDir(), "--rules=nope"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("args %v: expected exit code 2, got %d", args, code)
		}
	}
}

func TestScanMissingDir(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", filepath.Join(t.TempDir(), "nope")}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit code 2 for missing dir, got %d", code)
	}
}

func TestScanSarifFlag(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--format=sarif", dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d; stderr: %s", code, stderr.String())
	}
	var log map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &log); err != nil {
		t.Fatalf("sarif output not valid JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("wrong sarif version: %v", log["version"])
	}
}

func TestScanComplianceFilter(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--compliance", "CIS-AWS-1.5", "--format=json", dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	findings := env["findings"].([]any)
	if len(findings) == 0 {
		t.Fatal("expected CIS-mapped findings")
	}
	for _, f := range findings {
		fm := f.(map[string]any)
		compliance, ok := fm["compliance"].([]any)
		if !ok || len(compliance) == 0 {
			t.Errorf("finding %s missing compliance refs", fm["rule_id"])
			continue
		}
		for _, c := range compliance {
			cm := c.(map[string]any)
			if cm["framework"] != "CIS-AWS-1.5" {
				t.Errorf("filter leaked non-CIS ref: %v", cm)
			}
		}
	}
}

func TestScanComplianceInvalidFramework(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--compliance", "SOC2", dir}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "SOC2") {
		t.Errorf("error should name the bad framework, got: %s", errOut)
	}
	for _, fw := range []string{"CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-4.0"} {
		if !strings.Contains(errOut, fw) {
			t.Errorf("error should list available framework %s, got: %s", fw, errOut)
		}
	}
}

func TestScanComplianceTextShowsControls(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--compliance", "NIST-800-53", dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "compliance:") {
		t.Errorf("text output should show compliance controls, got:\n%s", stdout.String())
	}
}

func TestScanCustomRules(t *testing.T) {
	dir := t.TempDir()
	tf := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"b\"\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o644); err != nil {
		t.Fatal(err)
	}
	rulesDir := t.TempDir()
	yaml := "rules:\n- id: CUSTOM-T1\n  title: Team tag required\n  description: d\n  severity: high\n  resource_types: [aws_s3_bucket]\n  conditions: [{attribute: tags.Team, operator: absent}]\n"
	if err := os.WriteFile(filepath.Join(rulesDir, "r.yaml"), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--format=json", "--custom-rules", rulesDir, "--rules", "supplychain"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	found := false
	for _, f := range env["findings"].([]any) {
		if f.(map[string]any)["rule_id"] == "CUSTOM-T1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("CUSTOM-T1 not among findings: %s", stdout.String())
	}
}

func TestScanCustomRulesBadDir(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--custom-rules", filepath.Join(dir, "nope")}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit 2 (usage error), got %d; stderr: %s", code, stderr.String())
	}
}

func TestScanBaselineRoundtrip(t *testing.T) {
	dir := writeFixtures(t)
	baseline := filepath.Join(dir, "baseline.json")
	var stdout, stderr bytes.Buffer

	// Write baseline from current findings.
	code := run([]string{"scan", dir, "--format=json", "--baseline-out", baseline}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	if _, err := os.Stat(baseline); err != nil {
		t.Fatalf("baseline file not written: %v", err)
	}

	// Rescan with baseline: all fingerprinted findings suppressed.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"scan", dir, "--format=json", "--baseline", baseline}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0 (all baselined), got %d; stderr: %s; stdout: %s",
			code, stderr.String(), stdout.String())
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if findings := env["findings"].([]any); len(findings) != 0 {
		t.Fatalf("expected 0 findings after baseline, got %d", len(findings))
	}
}

func TestScanBaselineMissingFile(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--baseline", filepath.Join(dir, "nope.json")}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit 2 (usage error), got %d; stderr: %s", code, stderr.String())
	}
}

func TestScanInlineSuppression(t *testing.T) {
	dir := t.TempDir()
	tf := `# aegis:skip=AEGIS-AWS-001
resource "aws_s3_bucket" "skipped" {
  bucket = "skipped"
}

resource "aws_s3_bucket" "flagged" {
  bucket = "flagged"
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--format=json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	for _, f := range env["findings"].([]any) {
		fm := f.(map[string]any)
		if fm["rule_id"] == "AEGIS-AWS-001" && fm["resource"] == "aws_s3_bucket.skipped" {
			t.Errorf("suppressed finding leaked: AEGIS-AWS-001 on aws_s3_bucket.skipped")
		}
	}
	// The flagged bucket must still report 001.
	found := false
	for _, f := range env["findings"].([]any) {
		fm := f.(map[string]any)
		if fm["rule_id"] == "AEGIS-AWS-001" && fm["resource"] == "aws_s3_bucket.flagged" {
			found = true
		}
	}
	if !found {
		t.Error("expected AEGIS-AWS-001 on aws_s3_bucket.flagged")
	}
}

func TestScanCompleteness(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--format=json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings), got %d", code)
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	comp, ok := env["scan_completeness"].(map[string]any)
	if !ok {
		t.Fatalf("missing scan_completeness in JSON output")
	}
	if comp["files_discovered"].(float64) != 2 {
		t.Errorf("expected 2 files_discovered, got %v", comp["files_discovered"])
	}
	if comp["files_parsed"].(float64) != 2 {
		t.Errorf("expected 2 files_parsed, got %v", comp["files_parsed"])
	}
	if comp["files_failed"].(float64) != 0 {
		t.Errorf("expected 0 files_failed, got %v", comp["files_failed"])
	}
}

func TestScanCompletenessMalformed(t *testing.T) {
	dir := t.TempDir()
	badTF := "resource \"aws_s3_bucket\" \"bad\" { bucket = "
	if err := os.WriteFile(filepath.Join(dir, "bad.tf"), []byte(badTF), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--format=json"}, &stdout, &stderr)
	// Malformed file: scan completes but reports the failure
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, stdout.String())
	}
	comp, ok := env["scan_completeness"].(map[string]any)
	if !ok {
		t.Fatalf("missing scan_completeness in JSON output")
	}
	if comp["files_failed"].(float64) != 1 {
		t.Errorf("expected 1 files_failed, got %v", comp["files_failed"])
	}
	// Non-strict mode: exit code reflects findings (0 here), not parse errors
	if code != 0 {
		t.Errorf("expected exit 0 without --strict, got %d", code)
	}
}

func TestScanStrictFlag(t *testing.T) {
	dir := t.TempDir()
	badTF := "resource \"aws_s3_bucket\" \"bad\" { bucket = "
	if err := os.WriteFile(filepath.Join(dir, "bad.tf"), []byte(badTF), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--strict"}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 with --strict on malformed file, got %d; stderr: %s",
			code, stderr.String())
	}
	// Strict mode on clean input: normal exit codes apply
	dir2 := writeFixtures(t)
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"scan", dir2, "--strict", "--format=json"}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit 1 (findings) with --strict on valid input, got %d", code)
	}
}
