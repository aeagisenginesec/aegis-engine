package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pulumiVuln = `name: vuln
runtime: yaml
resources:
  data:
    type: aws:s3:Bucket
    properties:
      bucket: my-data
      acl: public-read
`

const pulumiSecure = `name: secure
runtime: yaml
resources:
  logs:
    type: aws:s3:Bucket
    properties:
      bucket: my-logs
      acl: private
`

const dockerfileVuln = `FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
USER root
`

// writeMixedDir creates a temp dir with Terraform, Pulumi, and Dockerfile
// sources for mixed-format scan tests.
func writeMixedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"main.tf":     vulnTF,
		"Pulumi.yaml": pulumiVuln,
		"Dockerfile":  dockerfileVuln,
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func scanJSON(t *testing.T, args ...string) (map[string]any, int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"scan"}, args...), &stdout, &stderr)
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstderr: %s\nstdout: %s", err, stderr.String(), stdout.String())
	}
	return env, code, stderr.String()
}

// The mixed-format directory must parse all three formats in one run, and
// scan completeness must report the per-file adapter format.
func TestScanMixedFormats(t *testing.T) {
	dir := writeMixedDir(t)
	env, code, _ := scanJSON(t, dir, "--format=json")
	if code != 1 {
		t.Fatalf("expected exit 1 (findings), got %d", code)
	}
	comp, ok := env["scan_completeness"].(map[string]any)
	if !ok {
		t.Fatalf("missing scan_completeness")
	}
	if comp["files_discovered"].(float64) != 3 {
		t.Errorf("files_discovered = %v, want 3", comp["files_discovered"])
	}
	if comp["files_parsed"].(float64) != 3 {
		t.Errorf("files_parsed = %v, want 3", comp["files_parsed"])
	}
	formats := map[string]bool{}
	files, _ := comp["files"].([]any)
	for _, f := range files {
		fm := f.(map[string]any)
		if fm["status"] != "parsed" {
			t.Errorf("file %v status = %v, want parsed", fm["path"], fm["status"])
		}
		formats[fm["format"].(string)] = true
	}
	for _, want := range []string{"terraform", "pulumi", "dockerfile"} {
		if !formats[want] {
			t.Errorf("format %q not reported in scan completeness; got %v", want, formats)
		}
	}
	// The Pulumi bucket must produce findings (public ACL rule).
	findings := env["findings"].([]any)
	if len(findings) == 0 {
		t.Fatalf("expected findings from mixed-format scan")
	}
}

// --exclude with globs skips matching files and reports them as skipped.
func TestScanExclude(t *testing.T) {
	dir := writeMixedDir(t)
	env, _, _ := scanJSON(t, dir, "--format=json", "--exclude=Pulumi.yaml,Dockerfile")
	comp := env["scan_completeness"].(map[string]any)
	if comp["files_parsed"].(float64) != 1 {
		t.Errorf("files_parsed = %v, want 1 (only main.tf)", comp["files_parsed"])
	}
	if comp["files_skipped"].(float64) != 2 {
		t.Errorf("files_skipped = %v, want 2", comp["files_skipped"])
	}
	files := comp["files"].([]any)
	for _, f := range files {
		fm := f.(map[string]any)
		if fm["status"] == "skipped" && !strings.Contains(fm["reason"].(string), "exclude") {
			t.Errorf("skipped file %v missing exclude reason: %v", fm["path"], fm["reason"])
		}
	}
}

// --exclude with ** glob.
func TestScanExcludeDoubleStar(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "vendor", "lib")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "vuln.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	env, _, _ := scanJSON(t, dir, "--format=json", "--exclude=vendor/**")
	comp := env["scan_completeness"].(map[string]any)
	if comp["files_parsed"].(float64) != 1 {
		t.Errorf("files_parsed = %v, want 1 (vendor/** excluded)", comp["files_parsed"])
	}
}

// --config severity overrides change reported severities.
func TestScanConfigSeverityOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vuln.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := "severity_overrides:\n  AEGIS-AWS-002: low\n"
	cfgPath := filepath.Join(dir, "aegis.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	env, _, _ := scanJSON(t, dir, "--format=json", "--config="+cfgPath)
	findings := env["findings"].([]any)
	found := false
	for _, f := range findings {
		fm := f.(map[string]any)
		if fm["rule_id"] == "AEGIS-AWS-002" {
			found = true
			if fm["severity"] != "low" {
				t.Errorf("AEGIS-AWS-002 severity = %v, want low (override)", fm["severity"])
			}
		}
	}
	if !found {
		t.Errorf("AEGIS-AWS-002 not among findings")
	}
}

// --config with exclude_rules drops the rule's findings.
func TestScanConfigExcludeRules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vuln.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "aegis.yaml")
	if err := os.WriteFile(cfgPath, []byte("exclude_rules:\n  - AEGIS-AWS-002\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env, _, _ := scanJSON(t, dir, "--format=json", "--config="+cfgPath)
	for _, f := range env["findings"].([]any) {
		if f.(map[string]any)["rule_id"] == "AEGIS-AWS-002" {
			t.Errorf("AEGIS-AWS-002 should have been excluded by config")
		}
	}
}

// --config with a missing file is a usage error.
func TestScanConfigMissingFile(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--config=" + filepath.Join(dir, "nope.yaml")}, &stdout, &stderr)
	if code != 2 {
		t.Errorf("expected exit 2 for missing config, got %d", code)
	}
}

// --compliance produces a pass/fail summary in JSON and text.
func TestScanComplianceSummary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vuln.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	env, _, _ := scanJSON(t, dir, "--format=json", "--compliance=CIS-AWS-1.5")
	sum, ok := env["compliance_summary"].(map[string]any)
	if !ok {
		t.Fatalf("missing compliance_summary in JSON output")
	}
	if sum["framework"] != "CIS-AWS-1.5" {
		t.Errorf("framework = %v", sum["framework"])
	}
	total := sum["controls_total"].(float64)
	passing := sum["controls_passing"].(float64)
	failing := sum["controls_failing"].(float64)
	if total <= 0 {
		t.Errorf("controls_total = %v, want > 0", total)
	}
	if passing+failing != total {
		t.Errorf("passing(%v)+failing(%v) != total(%v)", passing, failing, total)
	}
	if failing == 0 {
		t.Errorf("expected at least one failing control for the vulnerable fixture")
	}
	failed, _ := sum["failed_controls"].([]any)
	if len(failed) == 0 {
		t.Errorf("expected failed_controls list")
	}
	// Text output renders the summary line.
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--compliance=CIS-AWS-1.5"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if !strings.Contains(stdout.String(), "compliance CIS-AWS-1.5:") {
		t.Errorf("text output missing compliance summary line:\n%s", stdout.String())
	}
}

// Pulumi-only directory: vulnerable bucket fires, secure bucket is quiet.
func TestScanPulumiOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Pulumi.yaml"), []byte(pulumiVuln), 0o644); err != nil {
		t.Fatal(err)
	}
	env, code, _ := scanJSON(t, dir, "--format=json")
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	seen := map[string]bool{}
	for _, f := range env["findings"].([]any) {
		seen[f.(map[string]any)["rule_id"].(string)] = true
	}
	if !seen["AEGIS-AWS-002"] {
		t.Errorf("expected AEGIS-AWS-002 on Pulumi public bucket, got %v", seen)
	}

	dir2 := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir2, "Pulumi.yaml"), []byte(pulumiSecure), 0o644); err != nil {
		t.Fatal(err)
	}
	env2, _, _ := scanJSON(t, dir2, "--format=json")
	for _, f := range env2["findings"].([]any) {
		if f.(map[string]any)["rule_id"] == "AEGIS-AWS-002" {
			t.Errorf("AEGIS-AWS-002 should not fire on the private Pulumi bucket")
		}
	}
}
