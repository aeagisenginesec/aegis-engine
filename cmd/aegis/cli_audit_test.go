package main

// CLI surface audit tests (2026-10-14 mission, Part A).
//
// Characterization tests: they pin the audited CLI behavior — help-text
// accuracy, exit codes, output formats, determinism, and the
// --max-file-size over-cap behavior — so regressions surface as failures.
// They add no production code and change no rule or adapter logic.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"aegis/internal/discovery"
)

// documentedFlags extracts every --flag name mentioned in the CLI help text.
func documentedFlags(t *testing.T) []string {
	t.Helper()
	re := regexp.MustCompile(`--([a-z][a-z0-9-]*)`)
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(usageText, -1) {
		seen[m[1]] = true
	}
	var out []string
	for f := range seen {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// TestCLIAuditVersionStamped verifies --version prints the stamped release.
func TestCLIAuditVersionStamped(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("--version exited %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "2.0.0") {
		t.Errorf("--version output %q does not contain stamped version 2.0.0", stdout.String())
	}
}

// TestCLIAuditHelpDocumentsEveryFlag verifies the two directions of the
// help-text contract: every documented flag must exist, and every existing
// flag must be documented. (--attack-paths was the one historical gap;
// documented 2026-10-14, so the contract is now total.)
func TestCLIAuditHelpDocumentsEveryFlag(t *testing.T) {
	// Actual flag surface, verified against run()/runScan()/runFix()/
	// runQualityGate() and the manual serve flag parsing in main.go.
	actual := map[string]bool{}
	for _, f := range []string{
		// global (pre-command interception)
		"version",
		// scan
		"format", "rules", "advisories", "baseline", "baseline-out",
		"compliance", "custom-rules", "config", "exclude", "attack-paths",
		"max-file-size", "timeout", "strict", "fail-on", "color",
		// fix
		"apply", "force", "rule",
		// serve (manually parsed, not via flag.FlagSet)
		"addr", "auth-token",
		// quality-gate
		"bench-dir", "corpus-dir",
	} {
		actual[f] = true
	}
	// "format" is shared by scan, fix and quality-gate; dedupe is fine.

	documented := map[string]bool{}
	for _, f := range documentedFlags(t) {
		documented[f] = true
	}

	// Direction 1: every documented flag must exist.
	for f := range documented {
		if !actual[f] {
			t.Errorf("help documents --%s but no command implements it", f)
		}
	}

	// Direction 2: every existing flag must be documented. (--attack-paths
	// was the one historical gap; it has been documented, so no carve-out
	// remains.)
	var undocumented []string
	for f := range actual {
		if !documented[f] {
			undocumented = append(undocumented, f)
		}
	}
	sort.Strings(undocumented)
	if len(undocumented) > 0 {
		t.Errorf("implemented but undocumented flags: %v", undocumented)
	}
}

// TestCLIAuditExitCodes pins the exit-code contract: 0 = clean,
// 1 = findings, 2 = usage/scan error. The error exit must be distinct
// from the findings exit.
func TestCLIAuditExitCodes(t *testing.T) {
	vulnDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(vulnDir, "bad.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	emptyDir := t.TempDir()
	malformedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(malformedDir, "bad.tf"), []byte("resource \"x\" {\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	highsDir := t.TempDir()
	highsTF := "resource \"aws_s3_bucket\" \"s\" {\n  bucket = \"mybucket\"\n}\n"
	if err := os.WriteFile(filepath.Join(highsDir, "s.tf"), []byte(highsTF), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"clean dir", []string{"scan", emptyDir}, 0},
		{"findings dir", []string{"scan", vulnDir}, 1},
		{"nonexistent path", []string{"scan", filepath.Join(vulnDir, "nope")}, 2},
		{"file as target", []string{"scan", filepath.Join(vulnDir, "bad.tf")}, 2},
		{"no args", []string{}, 2},
		{"unknown subcommand", []string{"frobnicate", vulnDir}, 2},
		{"scan without dir", []string{"scan"}, 2},
		{"unknown format", []string{"scan", vulnDir, "--format=xml"}, 2},
		{"unknown rules pack", []string{"scan", vulnDir, "--rules=bogus"}, 2},
		{"bad fail-on", []string{"scan", vulnDir, "--fail-on=bogus"}, 2},
		{"bad compliance", []string{"scan", vulnDir, "--compliance=BOGUS"}, 2},
		{"missing baseline", []string{"scan", vulnDir, "--baseline=/nonexistent.json"}, 2},
		{"unknown scan flag", []string{"scan", vulnDir, "--nope"}, 2},
		// Malformed file, non-strict: parse failure is a diagnostic, the
		// exit code reflects findings (0 here) — not an error exit.
		{"malformed non-strict", []string{"scan", malformedDir}, 0},
		// --strict upgrades unparseable files to a scan error.
		{"malformed strict", []string{"scan", malformedDir, "--strict"}, 2},
		// --fail-on gates the findings exit on severity. vulnTF carries a
		// CRITICAL (AEGIS-AWS-104), so the critical gate still trips...
		{"fail-on critical with critical present", []string{"scan", vulnDir, "--fail-on=critical"}, 1},
		// ...but a highs-only tree stays below the critical gate.
		{"fail-on critical with highs only", []string{"scan", highsDir, "--fail-on=critical"}, 0},
		{"fail-on high with highs only", []string{"scan", highsDir, "--fail-on=high"}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(c.args, &stdout, &stderr); got != c.want {
				t.Errorf("run(%q) = %d, want %d; stderr: %s", c.args, got, c.want, stderr.String())
			}
		})
	}
}

// TestCLIAuditJSONFormat validates that --format=json emits parseable JSON
// carrying the findings with file:line spans.
func TestCLIAuditJSONFormat(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", dir, "--format=json"}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected exit 1, got %d; stderr: %s", code, stderr.String())
	}
	var doc struct {
		Version string `json:"aegis_version"`
		Target  string `json:"target"`
		Summary struct {
			Resources int `json:"resources"`
			Findings  int `json:"findings"`
			Critical  int `json:"critical"`
			High      int `json:"high"`
		} `json:"summary"`
		Findings []struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
			File     string `json:"file"`
			Line     int    `json:"line"`
			Evidence string `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("--format=json output is not valid JSON: %v", err)
	}
	if doc.Version != "2.0.0" {
		t.Errorf("aegis_version = %q, want 2.0.0", doc.Version)
	}
	if len(doc.Findings) == 0 {
		t.Fatal("JSON report carries no findings for a vulnerable fixture")
	}
	for _, f := range doc.Findings {
		if f.RuleID == "" || f.Severity == "" {
			t.Errorf("finding missing rule_id/severity: %+v", f)
		}
		if f.File == "" || f.Line < 1 {
			t.Errorf("finding %s missing file:line location: %+v", f.RuleID, f)
		}
		if f.Evidence == "" {
			t.Errorf("finding %s missing flat evidence string", f.RuleID)
		}
	}
	if doc.Summary.Findings != len(doc.Findings) {
		t.Errorf("summary.findings = %d, want %d", doc.Summary.Findings, len(doc.Findings))
	}
}

// TestCLIAuditSARIFFormat validates SARIF structure: version, runs,
// results, and rule metadata consistent with every result.
func TestCLIAuditSARIFFormat(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", dir, "--format=sarif"}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected exit 1, got %d; stderr: %s", code, stderr.String())
	}
	var doc struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("--format=sarif output is not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("sarif version = %q, want 2.1.0", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("sarif runs = %d, want 1", len(doc.Runs))
	}
	r := doc.Runs[0]
	if len(r.Results) == 0 {
		t.Fatal("sarif run has no results for a vulnerable fixture")
	}
	meta := map[string]bool{}
	for _, rule := range r.Tool.Driver.Rules {
		meta[rule.ID] = true
	}
	for _, res := range r.Results {
		if !meta[res.RuleID] {
			t.Errorf("sarif result references rule %q with no tool.driver.rules metadata", res.RuleID)
		}
		if len(res.Locations) == 0 || res.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
			t.Errorf("sarif result %q missing artifact location", res.RuleID)
		}
		if len(res.Locations) > 0 && res.Locations[0].PhysicalLocation.Region.StartLine < 1 {
			t.Errorf("sarif result %q missing startLine", res.RuleID)
		}
	}
}

// TestCLIAuditTextFormat checks the human-readable format carries
// severity-grouped sections and file:line locations on finding cards.
func TestCLIAuditTextFormat(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", dir}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected exit 1, got %d; stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	// Severity group headers, most severe first.
	for _, grp := range []string{"CRITICAL (", "HIGH ("} {
		if !strings.Contains(out, grp) {
			t.Errorf("text report missing %q group header;\n%s", grp, firstLines(out, 12))
		}
	}
	// Finding cards: rule + title line, then an indented file:line location.
	card := regexp.MustCompile(`(?m)^  AEGIS-[A-Z]+-\d+  .+\n    \S+:\d+  \S+`)
	if !card.MatchString(out) {
		t.Errorf("text report has no '<RULE>  <title>' / '<file>:<line>  <resource>' cards;\n%s",
			firstLines(out, 14))
	}
	if !strings.Contains(out, "evidence:") {
		t.Errorf("text report has no evidence lines;\n%s", firstLines(out, 14))
	}
}

// TestCLIAuditDeterministicOutput scans the same tree 5 times and requires
// byte-identical stdout for both text and JSON. No normalization: any
// nondeterminism (map iteration, concurrency, timestamps) fails the test.
func TestCLIAuditDeterministicOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "deep.tf"), []byte("resource \"aws_s3_bucket\" \"b2\" {\n  bucket = \"x\"\n  acl    = \"public-read\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			var first []byte
			for i := 0; i < 5; i++ {
				var stdout, stderr bytes.Buffer
				code := run([]string{"scan", dir, "--format=" + format}, &stdout, &stderr)
				if code != 1 {
					t.Fatalf("run %d: expected exit 1, got %d", i, code)
				}
				if i == 0 {
					first = stdout.Bytes()
					continue
				}
				if !bytes.Equal(first, stdout.Bytes()) {
					t.Fatalf("run %d output differs from run 0 (%d vs %d bytes)",
						i, len(first), len(stdout.Bytes()))
				}
			}
		})
	}
}

// TestCLIAuditMaxFileSizeCap pins the over-cap behavior: files at or under
// the cap are parsed; files over it are skipped with an explicit
// diagnostic naming the cap — never silently.
func TestCLIAuditMaxFileSizeCap(t *testing.T) {
	// The default cap is a code constant; pin it so a silent change fails.
	if discovery.MaxFileBytes != 10<<20 {
		t.Errorf("discovery.MaxFileBytes = %d, want %d (10 MiB)", discovery.MaxFileBytes, 10<<20)
	}
	// Shrink the cap for the test via the same override --max-file-size
	// uses; always restore afterwards so other tests are unaffected.
	discovery.SetMaxFileBytes(1024)
	t.Cleanup(func() { discovery.SetMaxFileBytes(0) })

	dir := t.TempDir()
	under := bytes.Repeat([]byte("#"), 1023)
	over := bytes.Repeat([]byte("#"), 1025)
	if err := os.WriteFile(filepath.Join(dir, "under.tf"), under, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "over.tf"), over, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	// Pass the flag explicitly too: the CLI path must honor it.
	code := run([]string{"scan", dir, "--format=json", "--max-file-size=1024"}, &stdout, &stderr)
	if code != 0 && code != 1 {
		t.Fatalf("scan exited %d; stderr: %s", code, stderr.String())
	}
	var doc struct {
		Diagnostics []struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		} `json:"diagnostics"`
		Completeness struct {
			Files []struct {
				Path   string `json:"path"`
				Status string `json:"status"`
				Reason string `json:"reason"`
			} `json:"files"`
		} `json:"scan_completeness"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("JSON output invalid: %v", err)
	}
	var sawOverDiag, sawOverSkipped bool
	var underCapSkipped bool
	for _, d := range doc.Diagnostics {
		if strings.Contains(d.Message, "over.tf") && strings.Contains(d.Message, "exceeds per-file cap") {
			sawOverDiag = true
		}
	}
	for _, f := range doc.Completeness.Files {
		switch {
		case strings.HasSuffix(f.Path, "over.tf"):
			if f.Status == "skipped" && strings.Contains(f.Reason, "exceeds per-file cap") {
				sawOverSkipped = true
			}
		case strings.HasSuffix(f.Path, "under.tf"):
			if f.Status == "skipped" && strings.Contains(f.Reason, "exceeds per-file cap") {
				underCapSkipped = true
			}
		}
	}
	if !sawOverDiag {
		t.Error("over-cap file produced no 'exceeds per-file cap' diagnostic (silent skip?)")
	}
	if !sawOverSkipped {
		t.Error("over-cap file not recorded as skipped with the cap reason in scan_completeness")
	}
	if underCapSkipped {
		t.Error("under-cap file was wrongly skipped for size")
	}
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// TestCLIAuditColorFlag checks --color=always forces ANSI colors even when
// stdout is not a terminal, --color=never suppresses them, and a bogus
// mode is rejected.
func TestCLIAuditColorFlag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.tf"), []byte(vulnTF), 0o644); err != nil {
		t.Fatal(err)
	}
	// always: colors even into a buffer.
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", dir, "--color=always"}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected exit 1, got %d; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "\x1b[") {
		t.Errorf("--color=always produced no ANSI codes")
	}
	// never: no colors.
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", dir, "--color=never"}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected exit 1, got %d; stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Errorf("--color=never produced ANSI codes")
	}
	// auto into a buffer: no colors (not a terminal).
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", dir}, &stdout, &stderr); code != 1 {
		t.Fatalf("expected exit 1, got %d; stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "\x1b[") {
		t.Errorf("--color=auto into a pipe produced ANSI codes")
	}
	// bogus mode rejected.
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", dir, "--color=rainbow"}, &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 for bad --color, got %d; stderr: %s", code, stderr.String())
	}
}

// TestResolveColor checks the --color mode mapping, including NO_COLOR
// and TERM=dumb handling in auto mode.
func TestResolveColor(t *testing.T) {
	var buf bytes.Buffer
	if c, ok := resolveColor("always", &buf); !ok || !c {
		t.Errorf("always: got %v,%v", c, ok)
	}
	if c, ok := resolveColor("never", &buf); !ok || c {
		t.Errorf("never: got %v,%v", c, ok)
	}
	if _, ok := resolveColor("rainbow", &buf); ok {
		t.Errorf("bogus mode should not be ok")
	}
	t.Setenv("NO_COLOR", "1")
	if c, ok := resolveColor("auto", &buf); !ok || c {
		t.Errorf("NO_COLOR should disable auto color: got %v,%v", c, ok)
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if c, ok := resolveColor("auto", &buf); !ok || c {
		t.Errorf("TERM=dumb should disable auto color: got %v,%v", c, ok)
	}
}
