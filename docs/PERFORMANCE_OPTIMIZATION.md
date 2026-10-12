# Performance Optimization Report

## Summary

Fixed the 9x performance regression in the Aegis rule engine pipeline.
The root cause was **not** the 587 rules — it was a pathological
inefficiency in the remediation enrichment phase.

### Before/After (vuln-200, 851 findings)

| Phase | Before | After | Improvement |
|-------|--------|-------|-------------|
| Discovery | 0.07ms | 0.07ms | — |
| Parsing | 10.7ms | 10.3ms | — |
| Registry | 0.27ms | 0.23ms | — |
| Rule engine (587 rules) | 14.5ms | 7.7ms | 1.9x |
| Compliance enrichment | 0.12ms | 0.04ms | 3x |
| Remediation enrichment | **438ms** | **1.4ms** | **313x** |
| **Total pipeline** | **464ms** | **20ms** | **23x** |
| CLI wall time | ~400ms | **40-78ms** | **~8x** |

## Root Cause

`ruleTitle()` in `internal/rules/remediation.go` was called for every
finding not in the detailed remediation DB (~800 findings on vuln-200).
Each call:
1. Built the full 587-rule registry via `DefaultRegistry()`
2. Sorted all 587 rules by ID string
3. Linear-scanned for the matching rule ID

**Cost:** 800 findings × (build + sort + scan) = 438ms (95% of total time)

## Fixes Applied

### 1. Cached rule title lookup (`internal/rules/remediation.go`)
- Added `sync.Once`-guarded `map[string]string` cache
- Registry built and titles cached exactly once per process
- Per-finding lookup is now O(1) map access

### 2. Cached sorted rules (`internal/rules/engine.go`)
- Added `sorted []ir.Rule` field to `Registry`
- Invalidated on `Register()`, rebuilt lazily on `All()`
- Added `sync.RWMutex` for thread-safe concurrent access
- Eliminates O(n log n) sort on every `Run()` call

## Detection Verification (Phase 5)

Zero finding loss across all corpora:

| Corpus | Before | After | Delta |
|--------|--------|-------|-------|
| vuln-200 | 851 | 851 | 0 |
| TerraGoat | 472 | 472 | 0 |
| vuln-22 | 105 | 105 | 0 |

## Test Results

- `go build ./...` ✅
- `go vet ./...` ✅
- `gofmt -l` ✅ clean
- `go test -count=1 ./...` ✅ all packages green
- `go test -race ./internal/rules/` ✅ no data races
- `aegis quality-gate` ✅ PASS (all 5 checks)
- `aegis doctor` ✅ 587 rules loaded

## Profiles

Saved in `benchmark/profiles/`:
- `cpu.prof`, `mem.prof` — baseline (pre-optimization)
- `cpu_long.prof` — extended run for hotspot analysis
- `cpu_optimized.prof`, `mem_optimized.prof` — post-optimization

## Performance Budget Status

| Benchmark | Target | Actual | Status |
|-----------|--------|--------|--------|
| vuln-200 | < 1,000ms | 40-78ms | ✅ PASS |
| Small corpora | < 100ms | 20-54ms | ✅ PASS |
| Detection | zero loss | zero loss | ✅ PASS |
| Memory | no increase | no increase | ✅ PASS |

## Key Insight

The 587-rule engine was never the problem — it runs in 7-14ms.
The regression was in the **enrichment pipeline**, not rule execution.
Always profile before optimizing.
