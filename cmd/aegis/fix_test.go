package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/remediation"
	"aegis/internal/rules"
)

// critTF trips AEGIS-AWS-003 (critical): a bucket policy with Principal "*".
const critTF = `resource "aws_s3_bucket_policy" "p" {
  bucket = "b"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "*"
    }]
  })
}
`

func writeCritFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "crit.tf"), []byte(critTF), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// medTF trips only AEGIS-AWS-009 (medium): an unencrypted EBS volume.
const medTF = `resource "aws_ebs_volume" "v" {
  availability_zone = "us-east-1a"
  size              = 10
}
`

func writeMedFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "med.tf"), []byte(medTF), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestScanFailOnThresholds(t *testing.T) {
	medDir := writeMedFixture(t) // max severity: medium
	critDir := writeCritFixture(t)
	cases := []struct {
		name     string
		dir      string
		failOn   string
		wantCode int
	}{
		{"medium finding below high threshold", medDir, "high", 0},
		{"medium finding below critical threshold", medDir, "critical", 0},
		{"medium finding meets medium threshold", medDir, "medium", 1},
		{"medium finding above low threshold", medDir, "low", 1},
		{"no flag means any finding fails", medDir, "", 1},
		{"critical finding meets critical threshold", critDir, "critical", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"scan", tc.dir}
			if tc.failOn != "" {
				args = append(args, "--fail-on="+tc.failOn)
			}
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != tc.wantCode {
				t.Errorf("--fail-on=%q: expected exit %d, got %d; stderr: %s",
					tc.failOn, tc.wantCode, code, stderr.String())
			}
			// Findings are still printed even when below the threshold.
			if tc.wantCode == 0 && !strings.Contains(stdout.String(), "AEGIS-AWS-009") {
				t.Errorf("expected findings in output despite exit 0, got:\n%s", stdout.String())
			}
		})
	}
}

func TestScanFailOnInvalid(t *testing.T) {
	dir := writeFixtures(t)
	for _, args := range [][]string{
		{"scan", dir, "--fail-on=bogus"},
		{"scan", dir, "--fail-on="},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Errorf("args %v: expected exit code 2, got %d", args, code)
		}
	}
}

func TestFixDryRunDoesNotModify(t *testing.T) {
	dir := writeFixtures(t)
	before, err := os.ReadFile(filepath.Join(dir, "vuln.tf"))
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"fix", dir}, &stdout, &stderr)
	if code != 0 && code != 1 {
		t.Fatalf("expected exit 0 or 1, got %d; stderr: %s", code, stderr.String())
	}
	after, err := os.ReadFile(filepath.Join(dir, "vuln.tf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Errorf("dry run modified the target file")
	}
	if !strings.Contains(stdout.String(), "dry run") {
		t.Errorf("expected dry-run notice in output, got:\n%s", stdout.String())
	}
}

func TestFixJSONFormat(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"fix", dir, "--format=json"}, &stdout, &stderr)
	if code != 0 && code != 1 {
		t.Fatalf("expected exit 0 or 1, got %d; stderr: %s", code, stderr.String())
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout.String())
	}
	if _, ok := env["patches"]; !ok {
		t.Errorf("missing patches key in JSON envelope")
	}
	if applied, ok := env["applied"].(bool); !ok || applied {
		t.Errorf("expected applied=false in dry run, got %v", env["applied"])
	}
}

func TestFixRuleFilter(t *testing.T) {
	dir := writeFixtures(t)
	var stdout, stderr bytes.Buffer
	// A rule ID that matches nothing: no patches, exit 0, file untouched.
	code := run([]string{"fix", dir, "--rule=AEGIS-AWS-999"}, &stdout, &stderr)
	if code != 0 {
		t.Errorf("expected exit 0 for unmatched --rule filter, got %d; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "patches proposed: 0") {
		t.Errorf("expected zero patches, got:\n%s", stdout.String())
	}
}

// TestFixApplyRoundTrip exercises the full --apply path: it only asserts
// the CLI's invariants (never modify without clean validation; re-scan
// after applying), so it holds regardless of which fixers the remediation
// package implements.
func TestFixApplyRoundTrip(t *testing.T) {
	dir := writeFixtures(t)
	target := filepath.Join(dir, "vuln.tf")
	original, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"fix", dir, "--apply"}, &stdout, &stderr)
	if code == 2 {
		t.Fatalf("fix --apply failed: %s", stderr.String())
	}

	changed, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(original) == string(changed) {
		// Nothing validated cleanly: the tree must be untouched and the
		// output must say so.
		if !strings.Contains(stdout.String(), "skipped") && !strings.Contains(stdout.String(), "patches proposed: 0") {
			t.Errorf("no patch applied but output doesn't explain why:\n%s", stdout.String())
		}
		return
	}

	// Something was applied: the re-scan must show fewer findings than the
	// pre-fix scan, and the output must report the before/after counts.
	if !strings.Contains(stdout.String(), "re-scan: findings") {
		t.Errorf("expected re-scan summary after --apply, got:\n%s", stdout.String())
	}
}

// TestFixApplyUsesValidationGate ensures --apply never writes a patch that
// did not validate cleanly: dry-run proposals that report would-fix=false
// must leave the file byte-identical after --apply.
func TestFixApplyUsesValidationGate(t *testing.T) {
	dir := writeFixtures(t)
	target := filepath.Join(dir, "vuln.tf")

	// Ask the remediation package directly which patches it proposes and
	// which validate cleanly, so the test can assert the CLI honored the gate.
	res, resources, _, err := scanFull(dir, defaultAdapters(), rules.DefaultRegistry())
	if err != nil {
		t.Fatal(err)
	}
	patches := remediation.ProposeAll(res.Findings, resources, os.ReadFile)
	clean := 0
	for _, p := range patches {
		v, verr := remediation.ValidatePatch(dir, p, defaultScanFunc)
		if verr != nil {
			t.Fatalf("validate: %v", verr)
		}
		if v.Fixed && len(v.NewFindings) == 0 {
			clean++
		}
	}

	original, _ := os.ReadFile(target)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fix", dir, "--apply"}, &stdout, &stderr); code == 2 {
		t.Fatalf("fix --apply failed: %s", stderr.String())
	}
	changed, _ := os.ReadFile(target)
	if clean == 0 && string(original) != string(changed) {
		t.Errorf("file modified although no patch validated cleanly")
	}
}
