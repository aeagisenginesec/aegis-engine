// Package regression holds golden-file tests that pin the full scan
// pipeline's output: adapter.ParseModule -> semantics resolution ->
// rules.DefaultRegistry().Run. Any change in parsing, resolution, or rule
// behavior that alters findings fails loudly with a diff.
//
// Regenerate the golden files after an intentional behavior change with:
//
//	AEGIS_UPDATE_GOLDEN=1 go test ./internal/regression/
//
// Review the git diff of testdata/*.golden.json before committing: the
// regeneration must reflect the intended change and nothing else.
package regression

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
	"aegis/internal/rules"
	"aegis/internal/semantics"
)

// fixtures are the regression corpus: one deliberately vulnerable config
// per file. rds_mixed also contains a hardened instance that must stay
// silent, pinning true negatives as well as true positives.
var fixtures = []string{"s3_insecure.tf", "sg_open.tf", "rds_mixed.tf"}

func TestRegression(t *testing.T) {
	for _, name := range fixtures {
		name := name
		t.Run(name, func(t *testing.T) {
			findings := scanFixture(t, name)
			got := marshalFindings(findings)
			goldenPath := filepath.Join("testdata", strings.TrimSuffix(name, ".tf")+".golden.json")
			if os.Getenv("AEGIS_UPDATE_GOLDEN") == "1" {
				if err := os.WriteFile(goldenPath, []byte(got), 0644); err != nil {
					t.Fatalf("writing golden file: %v", err)
				}
				t.Logf("regenerated %s (%d findings)", goldenPath, len(findings))
				return
			}
			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("golden file missing: run with AEGIS_UPDATE_GOLDEN=1 to generate it: %v", err)
			}
			if string(want) != got {
				t.Fatalf("findings changed for %s:\n%s", name, diffText(string(want), got))
			}
		})
	}
}

// scanFixture runs the full in-process pipeline for one fixture, mirroring
// cmd/aegis scanFull (minus discovery and module expansion — fixtures are
// single self-contained files with no module calls).
func scanFixture(t *testing.T, name string) []ir.Finding {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	// Parse with the bare fixture name (not the testdata path) so finding
	// spans are stable across machines and checkouts.
	mod, diags, err := terraform.New().ParseModule(name, src)
	if err != nil {
		t.Fatalf("parse hard error: %v", err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("parse error diagnostic: %s", d.Message)
		}
	}
	resources := append([]ir.Resource{}, mod.Resources...)
	resources = append(resources, mod.SyntheticResources...)
	scope := semantics.MergeModules([]terraform.Module{mod})
	resources = scope.ResolveResources(resources)
	findings := rules.DefaultRegistry().Run(resources)
	if findings == nil {
		findings = []ir.Finding{}
	}
	if len(findings) == 0 {
		t.Fatalf("fixture %s produced zero findings; a regression fixture must exercise rules", name)
	}
	return findings
}

// marshalFindings serializes findings as pretty JSON with a trailing
// newline, the exact bytes compared against the golden files.
func marshalFindings(findings []ir.Finding) string {
	b, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("marshaling findings: %v", err))
	}
	return string(b) + "\n"
}

// diffText renders a compact unified-style diff of two texts, truncated to
// 2000 characters. It shows the common-prefix line number where the texts
// first diverge plus a few lines of context on each side.
func diffText(want, got string) string {
	wl := strings.Split(want, "\n")
	gl := strings.Split(got, "\n")
	// Common prefix.
	p := 0
	for p < len(wl) && p < len(gl) && wl[p] == gl[p] {
		p++
	}
	// Common suffix.
	s := 0
	for s < len(wl)-p && s < len(gl)-p && wl[len(wl)-1-s] == gl[len(gl)-1-s] {
		s++
	}
	const ctx = 3
	var sb strings.Builder
	fmt.Fprintf(&sb, "first difference at line %d\n", p+1)
	start := p - ctx
	if start < 0 {
		start = 0
	}
	for i := start; i < p; i++ {
		fmt.Fprintf(&sb, "  %s\n", wl[i])
	}
	for i := p; i < len(wl)-s; i++ {
		fmt.Fprintf(&sb, "- %s\n", wl[i])
	}
	for i := p; i < len(gl)-s; i++ {
		fmt.Fprintf(&sb, "+ %s\n", gl[i])
	}
	end := len(wl) - s + ctx
	if end > len(wl) {
		end = len(wl)
	}
	for i := len(wl) - s; i < end; i++ {
		fmt.Fprintf(&sb, "  %s\n", wl[i])
	}
	out := sb.String()
	if len(out) > 2000 {
		out = out[:2000] + "\n... (diff truncated at 2000 chars)"
	}
	return out
}
