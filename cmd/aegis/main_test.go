package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/ir"
	"aegis/internal/rules"
	"aegis/internal/version"
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
	if env["aegis_version"] != version.Version {
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
	if !strings.Contains(stdout.String(), "findings:  0") {
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
	code := run([]string{"scan", "--compliance", "COBIT-2019", dir}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "COBIT-2019") {
		t.Errorf("error should name the bad framework, got: %s", errOut)
	}
	for _, fw := range []string{"CIS-AWS-1.5", "ISO-27001-2022", "NIST-800-53", "PCI-DSS-4.0", "SOC2"} {
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

func TestScanComplianceMultiFrameworkJSON(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--format", "json", "--compliance", "NIST-800-53,PCI-DSS-4.0", dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	var env struct {
		ComplianceSummary   *ir.ComplianceSummary   `json:"compliance_summary"`
		ComplianceSummaries []*ir.ComplianceSummary `json:"compliance_summaries"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if env.ComplianceSummary != nil {
		t.Error("multi-framework run should not set the singular compliance_summary")
	}
	if len(env.ComplianceSummaries) != 2 {
		t.Fatalf("expected 2 compliance summaries, got %d", len(env.ComplianceSummaries))
	}
	if env.ComplianceSummaries[0].Framework != "NIST-800-53" || env.ComplianceSummaries[1].Framework != "PCI-DSS-4.0" {
		t.Errorf("summaries out of order or wrong: %v", env.ComplianceSummaries)
	}
}

func TestScanComplianceAllFrameworks(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--format", "json", "--compliance", "all", dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	var env struct {
		ComplianceSummaries []*ir.ComplianceSummary `json:"compliance_summaries"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if len(env.ComplianceSummaries) != len(rules.ComplianceFrameworks()) {
		t.Fatalf("expected summaries for all %d frameworks, got %d",
			len(rules.ComplianceFrameworks()), len(env.ComplianceSummaries))
	}
}

func TestScanComplianceInvalidInList(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--compliance", "NIST-800-53,NOPE", dir}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "NOPE") {
		t.Errorf("error should name the bad framework, got: %s", stderr.String())
	}
}

func TestScanHTMLAttestation(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--format", "html", dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"<!DOCTYPE html>", "Compliance posture", "ISO-27001-2022", "HIPAA", "Findings"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML attestation should contain %q", want)
		}
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

func TestScanWaiverLifecycle(t *testing.T) {
	dir := writeFixtures(t)
	baseline := filepath.Join(dir, "baseline.json")
	var stdout, stderr bytes.Buffer

	// Author a waiver baseline: every current finding waived, owned,
	// expiring in 2099.
	code := run([]string{"scan", dir, "--baseline-out", baseline,
		"--waiver-reason", "legacy fixture debt", "--waiver-owner", "sec-team",
		"--waiver-expires", "2099-01-01T00:00:00Z"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	src, err := os.ReadFile(baseline)
	if err != nil {
		t.Fatalf("baseline not written: %v", err)
	}
	if !strings.Contains(string(src), "\"expires\": \"2099-01-01T00:00:00Z\"") ||
		!strings.Contains(string(src), "\"owner\": \"sec-team\"") {
		t.Fatalf("waiver metadata missing from baseline:\n%s", src)
	}

	// While the waiver lives: suppressed, and silent.
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"scan", dir, "--baseline", baseline}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0 under a live waiver, got %d; stderr: %s", code, stderr.String())
	}
	if strings.Contains(stderr.String(), "EXPIRED") {
		t.Fatalf("live waiver should not warn, got: %s", stderr.String())
	}

	// Expire the waiver: findings return AND the lapse is loud.
	expired := strings.ReplaceAll(string(src), "2099-01-01", "2000-01-01")
	if err := os.WriteFile(baseline, []byte(expired), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"scan", dir, "--baseline", baseline}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 after waiver expiry, got %d; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "waiver EXPIRED") {
		t.Fatalf("expired waiver should warn on stderr, got: %s", stderr.String())
	}
}

func TestScanWaiverBadExpiry(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--baseline-out", filepath.Join(dir, "b.json"),
		"--waiver-expires", "next-tuesday"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit 2 for unparseable --waiver-expires, got %d", code)
	}
	if !strings.Contains(stderr.String(), "waiver-expires") {
		t.Errorf("error should name the flag, got: %s", stderr.String())
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

// TestScanModuleDedup: a root that calls the same module twice, a nested
// module, and two different modules each holding a same-named bucket must
// produce exactly one finding per (rule, resource, attribute) — no bare
// twins — while keeping both same-named distinct resources.
func TestScanModuleDedup(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, src string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Root: two instances of ./mod-a, one of ./mod-b.
	write("main.tf", `
module "a1" { source = "./mod-a" }
module "a2" { source = "./mod-a" }
module "b"  { source = "./mod-b" }
resource "aws_s3_bucket" "root" {
  acl = "public-read"
}
`)
	// mod-a: one public bucket + a nested module call.
	write("mod-a/main.tf", `
resource "aws_s3_bucket" "data" {
  acl = "public-read"
}
module "inner" { source = "./inner" }
`)
	write("mod-a/inner/main.tf", `
resource "aws_s3_bucket" "deep" {
  acl = "public-read"
}
`)
	// mod-b: a same-named bucket (distinct resource, different file).
	write("mod-b/main.tf", `
resource "aws_s3_bucket" "data" {
  acl = "public-read"
}
`)
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--format=json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	findings, _ := env["findings"].([]any)
	// (rule, resource, evidence) triples must be unique: no bare twins.
	seen := map[string]int{}
	for _, f := range findings {
		fm := f.(map[string]any)
		key := fm["rule_id"].(string) + "|" + fm["resource"].(string) + "|" + fm["evidence"].(string)
		seen[key]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("duplicate finding %s x%d", k, n)
		}
	}
	// The public-ACL rule must fire exactly once per distinct bucket:
	// root, a1.data, a2.data, a1.inner.deep, a2.inner.deep, b.data = 6.
	var aclHits []string
	for _, f := range findings {
		fm := f.(map[string]any)
		if fm["rule_id"] == "AEGIS-AWS-002" {
			aclHits = append(aclHits, fm["resource"].(string))
		}
	}
	if len(aclHits) != 6 {
		t.Errorf("expected 6 AEGIS-AWS-002 findings (root + 2x mod-a + 2x nested + mod-b), got %d: %v", len(aclHits), aclHits)
	}
	// No bare finding may come from a module file: every finding whose
	// file is under mod-a/ or mod-b/ must carry a module address.
	for _, f := range findings {
		fm := f.(map[string]any)
		file := fm["file"].(string)
		res := fm["resource"].(string)
		if (strings.Contains(file, "mod-a/") || strings.Contains(file, "mod-b/")) && !strings.Contains(res, ".module.") {
			t.Errorf("bare twin survived: %s from %s", res, file)
		}
	}
}
