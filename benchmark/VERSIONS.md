# Phase 5 Benchmark — Frozen Versions

**Date:** 2026-10-11
**Corpus:** held-out, 200 projects, seed 999 (140 vuln / 60 clean)

> Frozen record of the **Oct-11 pre-FP-fix run** (326 rules). It does NOT
> describe the current `benchmark/heldout_results.json`: that file was
> regenerated 2026-11-25 from the current build under the medium+
> standard (see its `_meta` block and `docs/BENCHMARKS.md`). Do not cite
> the versions below as the versions behind the current results file.

| Component | Version |
|-----------|---------|
| Aegis binary | sha256: b44440068642532db45b2e95411f2cda6864616a691c5f0cdc8c3d2d0ab8e20e |
| Aegis rules | 326 (AEGIS-AWS-001–630, Azure, GCP, Docker, K8s, SC, TF) |
| Checkov | 3.3.26 |
| Go toolchain | go version go1.25.4 linux/amd64 |
| Platform | linux/amd64, 2-CPU sandbox |
