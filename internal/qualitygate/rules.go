package qualitygate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aegis/internal/ir"
	"aegis/internal/rules"
)

// runRuleCoverageGate verifies that every critical/high-severity rule in the
// default registry is referenced by at least one test file. A rule with no
// test is a release blocker: untested detection is unverified detection.
func runRuleCoverageGate(o Options) GateResult {
	registry := rules.DefaultRegistry()
	all := registry.All()

	var critHigh []ir.Rule
	for _, r := range all {
		if r.Severity() == ir.SeverityCritical || r.Severity() == ir.SeverityHigh {
			critHigh = append(critHigh, r)
		}
	}

	// Index rule IDs mentioned in _test.go files under the module.
	tested := map[string]bool{}
	err := filepath.Walk(o.ModuleRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(data)
		for _, r := range critHigh {
			if strings.Contains(text, r.ID()) {
				tested[r.ID()] = true
			}
		}
		return nil
	})
	if err != nil {
		return GateResult{
			Name:      "rule-coverage",
			Passed:    false,
			Metric:    "error",
			Threshold: "100% of critical/high rules tested",
			Details:   fmt.Sprintf("walk failed: %v", err),
		}
	}

	var missing []string
	for _, r := range critHigh {
		if !tested[r.ID()] {
			missing = append(missing, r.ID())
		}
	}
	passed := len(missing) == 0
	details := fmt.Sprintf("%d/%d critical/high rules have tests", len(critHigh)-len(missing), len(critHigh))
	if !passed {
		// Cap the list so output stays readable.
		shown := missing
		if len(shown) > 10 {
			shown = shown[:10]
		}
		details += "; missing: " + strings.Join(shown, ", ")
		if len(missing) > 10 {
			details += fmt.Sprintf(" (+%d more)", len(missing)-10)
		}
	}
	return GateResult{
		Name:      "rule-coverage",
		Passed:    passed,
		Metric:    fmt.Sprintf("%d/%d tested", len(critHigh)-len(missing), len(critHigh)),
		Threshold: "100% of critical/high rules tested",
		Details:   details,
	}
}
