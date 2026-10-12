// Package qualitygate implements Aegis's automated release gates.
//
// Phase 1 of the top-tier roadmap: measurable quality gates that block
// releases when detection accuracy, performance, or parser safety regress.
//
// Gates:
//   - PrecisionGate: ≥95% precision on the labeled benchmark
//   - RecallGate: ≥90% recall on the labeled benchmark
//   - RuleCoverageGate: 100% of critical/high rules have tests
//   - PerformanceGate: p95 scan time ≤500ms on the standard corpus
//   - ParserSafetyGate: malformed inputs produce explicit errors, never silent clean
//
// RunAll executes every gate and returns per-gate results. The benchmark
// gates skip gracefully when the labeled dataset is absent (e.g. the
// benchmark is still being generated).
package qualitygate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// Default locations. Overridable via Options for tests.
const (
	DefaultBenchDir  = "~/workspace/fpfn-bench"
	DefaultCorpusDir = "~/workspace/terraform/vuln-200"
)

// Thresholds from the roadmap's release-gate table.
const (
	PrecisionThreshold = 0.95
	RecallThreshold    = 0.90
	P95ThresholdMs     = 500
	PerfRuns           = 11 // odd count for a clean median
)

// GateResult is the outcome of one gate.
type GateResult struct {
	Name      string `json:"name"`
	Passed    bool   `json:"passed"`
	Skipped   bool   `json:"skipped,omitempty"`
	Metric    string `json:"metric"`
	Threshold string `json:"threshold"`
	Details   string `json:"details,omitempty"`
}

// Report is the full quality-gate run.
type Report struct {
	Gates  []GateResult `json:"gates"`
	Passed bool         `json:"passed"`
}

// Options configures a quality-gate run.
type Options struct {
	// BenchDir holds manifest.json + projects/ for the labeled benchmark.
	BenchDir string
	// CorpusDir is the standard corpus for the performance gate.
	CorpusDir string
	// ModuleRoot is the aegis-engine checkout (for rule-coverage checks).
	ModuleRoot string
	// Out receives human-readable output. Defaults to os.Stdout.
	Out io.Writer
}

// gate is one check run by RunAll.
type gate struct {
	name string
	run  func(o Options) GateResult
}

var allGates = []gate{
	{"precision", runPrecisionGate},
	{"recall", runRecallGate},
	{"rule-coverage", runRuleCoverageGate},
	{"performance", runPerformanceGate},
	{"parser-safety", runParserSafetyGate},
}

// RunAll executes every gate and returns the report.
func RunAll(o Options) Report {
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.BenchDir == "" {
		o.BenchDir = expandPath(DefaultBenchDir)
	}
	if o.CorpusDir == "" {
		o.CorpusDir = expandPath(DefaultCorpusDir)
	}
	if o.ModuleRoot == "" {
		o.ModuleRoot = moduleRoot()
	}
	rep := Report{}
	for _, g := range allGates {
		res := g.run(o)
		rep.Gates = append(rep.Gates, res)
		if !res.Passed && !res.Skipped {
			rep.Passed = false
		}
	}
	// Passed is true only if every non-skipped gate passed.
	rep.Passed = true
	for _, gr := range rep.Gates {
		if !gr.Skipped && !gr.Passed {
			rep.Passed = false
			break
		}
	}
	return rep
}

// PrintReport writes a human-readable summary.
func PrintReport(rep Report, w io.Writer) {
	for _, g := range rep.Gates {
		status := "FAIL"
		if g.Skipped {
			status = "SKIP"
		} else if g.Passed {
			status = "PASS"
		}
		fmt.Fprintf(w, "[%s] %-14s metric=%s threshold=%s\n", status, g.Name, g.Metric, g.Threshold)
		if g.Details != "" {
			fmt.Fprintf(w, "       %s\n", g.Details)
		}
	}
	if rep.Passed {
		fmt.Fprintln(w, "\nQUALITY GATE: PASS — release may proceed")
	} else {
		fmt.Fprintln(w, "\nQUALITY GATE: FAIL — release blocked")
	}
}

// PrintJSON writes the machine-parseable report.
func PrintJSON(rep Report, w io.Writer) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(rep)
}

func expandPath(p string) string {
	if len(p) > 1 && p[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// moduleRoot locates the aegis-engine checkout by walking up from the
// current working directory looking for go.mod with module aegis.
func moduleRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if data, err := os.ReadFile(filepath.Join(dir, "go.mod")); err == nil {
			for _, line := range splitLines(string(data)) {
				if line == "module aegis" {
					return dir
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// sortedKeys returns map keys in sorted order (deterministic output).
func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
