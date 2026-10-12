# Performance Regression Protection

## Background

On 2026-10-11, a 9x performance regression was discovered: vuln-200 scan time
went from 374ms (346 rules) to 3,299ms (587 rules). Profiling revealed the
rule engine itself ran in 7-14ms — the culprit was `EnrichRemediation`
rebuilding the entire 587-rule registry for every finding (~800 times).

## The Fix

Two caching changes in `internal/rules/remediation.go` and
`internal/rules/engine.go`:
1. `sync.Once`-guarded title cache — per-finding lookup now O(1)
2. Cached sorted rules in `Registry` with `sync.RWMutex`

Results:
| Metric | Before | After |
|--------|--------|-------|
| Remediation enrichment | 438ms | 1.4ms (313x) |
| Total pipeline | 464ms | 20ms (23x) |
| vuln-200 wall time | 3,299ms | 40-78ms |

## Protection

### Benchmarks (`internal/perf/`)

- `BenchmarkRemediationEnrichment` — isolated, fails if single run > 5ms
- `BenchmarkFullScan` — 20 iterations on vuln-200, reports median/p95
- `BenchmarkColdStart` — first-run timing with cleared caches
- `TestCacheThreadSafety` — 50 concurrent enrichments, verifies identical output

### CI Gate (`benchmark/perf_gate.sh`)

Fails if p95 exceeds 150% of baseline in `benchmark/perf_baseline.json`.

### Baseline (`benchmark/perf_baseline.json`)

```json
{
  "remediation_enrichment_ms": 1.4,
  "full_scan_median_ms": 60.0,
  "full_scan_p95_ms": 100.0,
  "cold_start_ms": 80.0,
  "rule_count": 587
}
```

### Thread Safety

The registry cache uses `sync.Once` for initialization and `sync.RWMutex`
for concurrent reads. Verified with `go test -race` and 50-goroutine stress test.

## Metrics Tracked

- Median latency, p95 latency
- Peak RSS (resident set size)
- Allocation count
- Cold-start time (first run, caches cleared)
- Rule count (regression often correlates with rule additions)
