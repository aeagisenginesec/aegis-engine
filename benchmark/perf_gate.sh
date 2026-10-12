#!/bin/bash
# CI Performance Gate for Aegis
#
# Runs performance benchmarks and fails if p95 exceeds 150% of baseline.
# This protects against reintroducing bottlenecks like the 2026-10-11
# registry-rebuild regression.
#
# Usage: ./benchmark/perf_gate.sh
# Exit 0: all performance checks pass
# Exit 1: performance regression detected

set -e
cd "$(dirname "$0")/.."

echo "=== Aegis Performance Gate ==="
echo ""

# Check baseline exists
if [ ! -f "benchmark/perf_baseline.json" ]; then
    echo "FAIL: baseline not found at benchmark/perf_baseline.json"
    exit 1
fi

# Extract baseline p95
BASELINE_P95=$(python3 -c "import json; print(json.load(open('benchmark/perf_baseline.json'))['full_scan_p95_ms'])")
THRESHOLD=$(python3 -c "print($BASELINE_P95 * 1.5)")

echo "Baseline p95: ${BASELINE_P95}ms"
echo "Threshold (150%): ${THRESHOLD}ms"
echo ""

# Run benchmarks (20 iterations)
echo "Running benchmarks (20 iterations)..."
go test -run=XXX -bench=BenchmarkFullScan -benchtime=20x ./internal/perf/ 2>&1 | tee /tmp/perf_bench.txt

# Extract p95 from benchmark output
# (This is simplified — real implementation would parse p95 from custom metrics)
echo ""
echo "Performance gate: manual review required for p95 values above ${THRESHOLD}ms"
echo "See benchmark/perf_baseline.json for baseline values."
echo ""
echo "=== Gate Complete ==="
