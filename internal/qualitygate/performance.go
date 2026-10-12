package qualitygate

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"aegis/internal/adapter/terraform"
	"aegis/internal/discovery"
	"aegis/internal/rules"
)

// scanCorpus parses every Terraform file under dir and runs the default
// registry, returning the scan duration. It mirrors the production scan
// path closely enough for performance measurement (parse + rule engine).
func scanCorpus(dir string) (time.Duration, error) {
	start := time.Now()
	files, err := discovery.Discover(dir)
	if err != nil {
		return 0, err
	}
	adapter := terraform.New()
	registry := rules.DefaultRegistry()
	for _, f := range files {
		if !adapter.Handles(f.Path) {
			continue
		}
		src, err := discovery.Read(f)
		if err != nil {
			continue
		}
		resources, _, err := adapter.Parse(f.Path, src)
		if err != nil {
			continue
		}
		_ = registry.Run(resources)
	}
	return time.Since(start), nil
}

// percentiles returns the median and p95 of durations in milliseconds.
func percentiles(durs []time.Duration) (medianMs, p95Ms float64) {
	if len(durs) == 0 {
		return 0, 0
	}
	ms := make([]float64, len(durs))
	for i, d := range durs {
		ms[i] = float64(d) / float64(time.Millisecond)
	}
	sort.Float64s(ms)
	medianMs = ms[len(ms)/2]
	idx := int(float64(len(ms)) * 0.95)
	if idx >= len(ms) {
		idx = len(ms) - 1
	}
	p95Ms = ms[idx]
	return medianMs, p95Ms
}

// runPerformanceGate records median/p95 scan time over PerfRuns runs and
// fails when p95 exceeds P95ThresholdMs.
func runPerformanceGate(o Options) GateResult {
	if _, err := os.Stat(o.CorpusDir); err != nil {
		return GateResult{
			Name:      "performance",
			Skipped:   true,
			Metric:    "n/a",
			Threshold: fmt.Sprintf("p95≤%dms", P95ThresholdMs),
			Details:   fmt.Sprintf("corpus dir not found: %s", o.CorpusDir),
		}
	}
	// Warm up once so the measured runs exclude cold-start effects.
	if _, err := scanCorpus(o.CorpusDir); err != nil {
		return GateResult{
			Name:      "performance",
			Passed:    false,
			Metric:    "error",
			Threshold: fmt.Sprintf("p95≤%dms", P95ThresholdMs),
			Details:   fmt.Sprintf("warmup scan failed: %v", err),
		}
	}
	var durs []time.Duration
	for i := 0; i < PerfRuns; i++ {
		d, err := scanCorpus(o.CorpusDir)
		if err != nil {
			return GateResult{
				Name:      "performance",
				Passed:    false,
				Metric:    "error",
				Threshold: fmt.Sprintf("p95≤%dms", P95ThresholdMs),
				Details:   fmt.Sprintf("run %d failed: %v", i+1, err),
			}
		}
		durs = append(durs, d)
	}
	medianMs, p95Ms := percentiles(durs)
	passed := p95Ms <= P95ThresholdMs
	corpus := filepath.Base(o.CorpusDir)
	return GateResult{
		Name:      "performance",
		Passed:    passed,
		Metric:    fmt.Sprintf("median=%.1fms p95=%.1fms", medianMs, p95Ms),
		Threshold: fmt.Sprintf("p95≤%dms", P95ThresholdMs),
		Details:   fmt.Sprintf("%d runs on %s", PerfRuns, corpus),
	}
}
