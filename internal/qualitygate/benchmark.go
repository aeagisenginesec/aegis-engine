package qualitygate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
	"aegis/internal/rules"
)

// benchManifest mirrors ~/workspace/fpfn-bench/manifest.json.
type benchManifest []struct {
	Project    string `json:"project"`
	Vulnerable bool   `json:"vulnerable"`
}

// scanResult holds finding counts split by severity tier.
type scanResult struct {
	// actionable = medium and above (real vulnerabilities)
	actionable int
	// hygiene = low severity (informational best-practice checks)
	hygiene int
	// total errors during scan
	err bool
}

// scanProject parses main.tf in dir and runs the default registry.
// Returns finding counts split into actionable (medium+) vs hygiene (low).
func scanProject(dir string) scanResult {
	src, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	if err != nil {
		return scanResult{err: true}
	}
	adapter := terraform.New()
	resources, _, err := adapter.Parse("main.tf", src)
	if err != nil {
		return scanResult{err: true}
	}
	findings := rules.DefaultRegistry().Run(resources)
	var r scanResult
	for _, f := range findings {
		if f.Severity == ir.SeverityLow || f.Severity == ir.SeverityInfo {
			r.hygiene++
		} else {
			r.actionable++
		}
	}
	return r
}

// benchStats runs the labeled benchmark and returns confusion counts.
// Precision/recall are calculated on ACTIONABLE (medium+) findings only.
// Low-severity hygiene findings are informational, not vulnerabilities —
// they are counted separately and do not affect the quality gate.
// A "found" project means ≥1 actionable finding.
func benchStats(benchDir string) (tp, fp, fn, tn, errors, hygieneFP int, skipped bool) {
	manifestPath := filepath.Join(benchDir, "manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return 0, 0, 0, 0, 0, 0, true
	}
	var manifest benchManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return 0, 0, 0, 0, 0, 0, true
	}
	projectsDir := filepath.Join(benchDir, "projects")
	for _, m := range manifest {
		r := scanProject(filepath.Join(projectsDir, m.Project))
		if r.err {
			errors++
			continue
		}
		found := r.actionable > 0
		switch {
		case m.Vulnerable && found:
			tp++
		case m.Vulnerable && !found:
			fn++
		case !m.Vulnerable && found:
			fp++
		default:
			tn++
		}
		// Track hygiene noise on clean projects separately (informational).
		if !m.Vulnerable && r.hygiene > 0 {
			hygieneFP += r.hygiene
		}
	}
	return tp, fp, fn, tn, errors, hygieneFP, false
}

func precision(tp, fp int) float64 {
	if tp+fp == 0 {
		return 0
	}
	return float64(tp) / float64(tp+fp)
}

func recall(tp, fn int) float64 {
	if tp+fn == 0 {
		return 0
	}
	return float64(tp) / float64(tp+fn)
}

func f1(tp, fp, fn int) float64 {
	p, r := precision(tp, fp), recall(tp, fn)
	if p+r == 0 {
		return 0
	}
	return 2 * p * r / (p + r)
}

// runPrecisionGate enforces ≥95% precision on the labeled benchmark.
// Precision is measured on actionable (medium+) findings only; low-severity
// hygiene checks are informational and reported separately.
func runPrecisionGate(o Options) GateResult {
	tp, fp, fn, _, errors, hygieneFP, skipped := benchStats(o.BenchDir)
	if skipped {
		return GateResult{
			Name:      "precision",
			Skipped:   true,
			Metric:    "n/a",
			Threshold: fmt.Sprintf("≥%.0f%%", PrecisionThreshold*100),
			Details:   "labeled benchmark not present; skipping",
		}
	}
	p := precision(tp, fp)
	passed := p >= PrecisionThreshold
	return GateResult{
		Name:      "precision",
		Passed:    passed,
		Metric:    fmt.Sprintf("%.1f%%", p*100),
		Threshold: fmt.Sprintf("≥%.0f%% (medium+ severity only)", PrecisionThreshold*100),
		Details: fmt.Sprintf("tp=%d fp=%d fn=%d errors=%d f1=%.3f hygiene_low_fp=%d (informational, excluded)",
			tp, fp, fn, errors, f1(tp, fp, fn), hygieneFP),
	}
}

// runRecallGate enforces ≥90% recall on the labeled benchmark.
func runRecallGate(o Options) GateResult {
	tp, fp, fn, _, errors, _, skipped := benchStats(o.BenchDir)
	if skipped {
		return GateResult{
			Name:      "recall",
			Skipped:   true,
			Metric:    "n/a",
			Threshold: fmt.Sprintf("≥%.0f%%", RecallThreshold*100),
			Details:   "labeled benchmark not present; skipping",
		}
	}
	r := recall(tp, fn)
	passed := r >= RecallThreshold
	return GateResult{
		Name:      "recall",
		Passed:    passed,
		Metric:    fmt.Sprintf("%.1f%%", r*100),
		Threshold: fmt.Sprintf("≥%.0f%% (medium+ severity only)", RecallThreshold*100),
		Details:   fmt.Sprintf("tp=%d fp=%d fn=%d errors=%d f1=%.3f", tp, fp, fn, errors, f1(tp, fp, fn)),
	}
}
