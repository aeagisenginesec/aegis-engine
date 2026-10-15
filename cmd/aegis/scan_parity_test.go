package main

// scan_parity_test.go — cross-format differential parity tests.
//
// Reads benchmark/parity/fixtures/<control>/<variant>/<format>/, each
// containing input files plus a recorded expect.json (see
// benchmark/parity/record.py). For every fixture it asserts:
//
//  1. Regression: current scan matches the recorded expect.json
//     (normalized findings, completeness, diagnostics count).
//  2. Determinism: 3 consecutive scans produce identical finding hashes.
//  3. Cross-format parity: within one <control>/<variant>, every format
//     produces the same multiset of (rule_id, severity, resource_type).
//  4. Completeness: no file silently omitted (discovered == inputs).
//
// Findings are normalized to (rule_id, severity, resource_type):
// resource NAMES are format-specific (TF label vs CFN logical ID) and
// are stripped for cross-format comparison, but counts are preserved.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const parityFixtureRoot = "../../benchmark/parity/fixtures"

type normFinding struct {
	RuleID       string
	Severity     string
	ResourceType string
}

func (n normFinding) key() string { return n.RuleID + "|" + n.Severity + "|" + n.ResourceType }

type expectFile struct {
	Control  string   `json:"control"`
	Variant  string   `json:"variant"`
	Format   string   `json:"format"`
	Files    []string `json:"files"`
	ExitCode int      `json:"exit_code"`
	Findings []struct {
		RuleID       string `json:"rule_id"`
		Severity     string `json:"severity"`
		ResourceType string `json:"resource_type"`
		Count        int    `json:"count"`
	} `json:"findings"`
	FindingTotal  int  `json:"finding_total"`
	Diagnostics   int  `json:"diagnostics"`
	Deterministic bool `json:"deterministic"`
	Completeness  struct {
		Discovered int `json:"discovered"`
		Parsed     int `json:"parsed"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"completeness"`
}

type scanOut struct {
	Findings []struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Resource string `json:"resource"`
	} `json:"findings"`
	Diagnostics  []any `json:"diagnostics"`
	Completeness struct {
		Discovered int `json:"files_discovered"`
		Parsed     int `json:"files_parsed"`
		Skipped    int `json:"files_skipped"`
		Failed     int `json:"files_failed"`
	} `json:"scan_completeness"`
}

func parityScan(t *testing.T, dir string) scanOut {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", "--format=json", dir}, &stdout, &stderr)
	_ = code
	var out scanOut
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("scan %s: stdout not JSON: %v\nstderr: %s", dir, err, stderr.String())
	}
	return out
}

func normalizeFindings(out scanOut) []normFinding {
	var n []normFinding
	for _, f := range out.Findings {
		rt := f.Resource
		if i := strings.LastIndex(rt, "."); i >= 0 {
			rt = rt[:i]
		}
		n = append(n, normFinding{RuleID: f.RuleID, Severity: f.Severity, ResourceType: rt})
	}
	sort.Slice(n, func(i, j int) bool { return n[i].key() < n[j].key() })
	return n
}

func hashFindings(n []normFinding) string {
	var sb strings.Builder
	for _, f := range n {
		sb.WriteString(f.key())
		sb.WriteString(";")
	}
	h := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(h[:])
}

type fixture struct {
	control, variant, format, dir string
	expect                        expectFile
}

// collectFixtures walks the fixture tree.
func collectFixtures(t *testing.T) []fixture {
	t.Helper()
	var out []fixture
	controls, err := os.ReadDir(parityFixtureRoot)
	if err != nil {
		t.Skipf("parity fixtures not present: %v", err)
	}
	for _, c := range controls {
		if !c.IsDir() {
			continue
		}
		variants, _ := os.ReadDir(filepath.Join(parityFixtureRoot, c.Name()))
		for _, v := range variants {
			if !v.IsDir() {
				continue
			}
			formats, _ := os.ReadDir(filepath.Join(parityFixtureRoot, c.Name(), v.Name()))
			for _, f := range formats {
				if !f.IsDir() {
					continue
				}
				dir := filepath.Join(parityFixtureRoot, c.Name(), v.Name(), f.Name())
				raw, err := os.ReadFile(filepath.Join(dir, "expect.json"))
				if err != nil {
					t.Errorf("fixture %s: missing expect.json (run record.py)", dir)
					continue
				}
				var e expectFile
				if err := json.Unmarshal(raw, &e); err != nil {
					t.Errorf("fixture %s: bad expect.json: %v", dir, err)
					continue
				}
				out = append(out, fixture{c.Name(), v.Name(), f.Name(), dir, e})
			}
		}
	}
	if len(out) == 0 {
		t.Skip("no parity fixtures found")
	}
	return out
}

// TestParityRegression: current output matches recorded expectations.
func TestParityRegression(t *testing.T) {
	for _, fx := range collectFixtures(t) {
		fx := fx
		name := fmt.Sprintf("%s/%s/%s", fx.control, fx.variant, fx.format)
		t.Run(name, func(t *testing.T) {
			out := parityScan(t, fx.dir)
			got := normalizeFindings(out)

			// expand expected multiset
			var want []normFinding
			for _, f := range fx.expect.Findings {
				for i := 0; i < f.Count; i++ {
					want = append(want, normFinding{f.RuleID, f.Severity, f.ResourceType})
				}
			}
			sort.Slice(want, func(i, j int) bool { return want[i].key() < want[j].key() })

			if len(got) != len(want) {
				t.Errorf("finding count: got %d, want %d", len(got), len(want))
			}
			gotKeys := map[string]int{}
			for _, n := range got {
				gotKeys[n.key()]++
			}
			wantKeys := map[string]int{}
			for _, n := range want {
				wantKeys[n.key()]++
			}
			for k, w := range wantKeys {
				if gotKeys[k] != w {
					t.Errorf("finding %s: got %d, want %d", k, gotKeys[k], w)
				}
			}
			for k, g := range gotKeys {
				if wantKeys[k] == 0 {
					t.Errorf("unexpected finding %s x%d", k, g)
				}
			}
			if len(out.Diagnostics) != fx.expect.Diagnostics {
				t.Errorf("diagnostics: got %d, want %d", len(out.Diagnostics), fx.expect.Diagnostics)
			}
			c := out.Completeness
			if c.Discovered != fx.expect.Completeness.Discovered ||
				c.Parsed != fx.expect.Completeness.Parsed ||
				c.Failed != fx.expect.Completeness.Failed {
				t.Errorf("completeness: got %+v, want %+v", c, fx.expect.Completeness)
			}
		})
	}
}

// TestParityDeterminism: 3 runs -> identical finding hash.
func TestParityDeterminism(t *testing.T) {
	for _, fx := range collectFixtures(t) {
		fx := fx
		name := fmt.Sprintf("%s/%s/%s", fx.control, fx.variant, fx.format)
		t.Run(name, func(t *testing.T) {
			hashes := map[string]bool{}
			for i := 0; i < 3; i++ {
				out := parityScan(t, fx.dir)
				hashes[hashFindings(normalizeFindings(out))] = true
			}
			if len(hashes) != 1 {
				t.Errorf("non-deterministic: %d distinct hashes", len(hashes))
			}
		})
	}
}

// TestParityCrossFormat: within one control+variant, all formats agree.
func TestParityCrossFormat(t *testing.T) {
	type cv struct{ control, variant string }
	groups := map[cv][]fixture{}
	for _, fx := range collectFixtures(t) {
		k := cv{fx.control, fx.variant}
		groups[k] = append(groups[k], fx)
	}
	for k, fxs := range groups {
		k, fxs := k, fxs
		if len(fxs) < 2 {
			continue
		}
		name := fmt.Sprintf("%s/%s", k.control, k.variant)
		t.Run(name, func(t *testing.T) {
			sets := map[string]map[string]int{}
			for _, fx := range fxs {
				out := parityScan(t, fx.dir)
				m := map[string]int{}
				for _, n := range normalizeFindings(out) {
					m[n.key()]++
				}
				sets[fx.format] = m
			}
			formats := make([]string, 0, len(sets))
			for f := range sets {
				formats = append(formats, f)
			}
			sort.Strings(formats)
			base := formats[0]
			for _, other := range formats[1:] {
				diff := diffMultisets(sets[base], sets[other])
				if diff != "" {
					t.Errorf("parity gap %s vs %s:\n%s", base, other, diff)
				}
			}
		})
	}
}

func diffMultisets(a, b map[string]int) string {
	var sb strings.Builder
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	for k := range keys {
		if a[k] != b[k] {
			fmt.Fprintf(&sb, "  %s: %d vs %d\n", k, a[k], b[k])
		}
	}
	return sb.String()
}
