# vuln-100000 Mega-Scale Benchmark

**Date:** 2026-10-18
**Aegis:** 2.0.0 @ `a35a33e` (the Oct 16 S3-correlation perf fix; engine code unchanged since the vuln-10000 re-benchmark)
**Fixture:** `~/workspace/vuln-100000/` — 100,001 files (100,000 deliberately vulnerable + README), 1,773,182 lines, 391 MB
**Generator:** `~/workspace/vuln-1000-gen.py` with `VULN_ROOT=~/workspace/vuln-100000 VULN_SCALE=100` (seed 1000, deterministic; generation wall time 24 s)

## Fixture distribution

| Type | Files |
|---|---|
| Terraform AWS | 25,000 |
| Terraform Azure | 20,000 |
| Terraform GCP | 15,000 |
| Dockerfiles | 10,000 |
| Kubernetes | 15,000 |
| CloudFormation | 10,000 |
| Docker Compose | 5,000 |
| **Total vulnerable** | **100,000** |

## Methodology note: safety caps

Stock Aegis 2.0.0 hardcodes discovery safety caps (`internal/discovery/discovery.go`):
`MaxFiles = 20000` and `MaxTotalBytes = 256 MiB`. A first attempt at the
100k scan stopped after 20,000 files with the diagnostic
"scan stopped: file-count cap 20000 reached …; remaining files not scanned"
(exit 1, 208,796 findings on the 20k subset — a real product limitation worth
knowing: **out of the box, 2.0.0 will not scan more than 20,000 files or
256 MiB per invocation**).

For this benchmark both caps were **temporarily** raised
(`MaxFiles = 200000`, `MaxTotalBytes = 1024 MiB`), the binary rebuilt, the
three scans run, then the change **reverted** and the binary rebuilt from the
clean tree. No commits were made. The numbers below therefore measure the
2.0.0 engine at 100k files, not the stock safety defaults.

## Results (3 JSON runs, 100,000/100,000 files parsed)

| Run | Wall time | Peak RSS | Findings |
|---|---|---|---|
| 1 | 148.30 s (2:28) | 5,735,912 KB (5.60 GB) | 1,003,677 |
| 2 | 129.77 s (2:10) | 5,353,892 KB (5.23 GB) | 1,003,677 |
| 3 | 124.78 s (2:05) | 5,637,912 KB (5.51 GB) | 1,003,677 |

**Findings breakdown:** 47,762 critical / 282,562 high / 380,548 medium / 292,805 low
**Resources:** 153,873 · **Distinct rules fired:** 231 · **Files parsed:** 100,000/100,000 (zero skipped, zero failed, zero diagnostics)

## Correctness

- **Determinism:** all 3 runs byte-identical finding sets (SHA-256 of rule/file/line/severity tuples matched across runs).
- **Cross-scale consistency:** severity ratios hold from 10k → 100k
  (critical 4.87%→4.76%, high 28.07%→28.15%, medium 37.86%→37.91%,
  low 29.21%→29.17%) and findings-per-file is flat
  (10.09 → 10.04). The engine is counting the same things at 10× scale.
- **Accuracy spot-check:** not re-run at this scale; 8/8 true positives were
  verified on vuln-10000 and the rule set is unchanged since.

## Scaling analysis (honest)

| Fixture | Files | Findings | Wall time (fixed engine) | Peak RSS |
|---|---|---|---|---|
| vuln-1000 | 1,000 | 9,719 | ~0.5 s | <90 MB |
| vuln-4000 | 4,000 | 39,543 | ~5.5 s | ~315 MB |
| vuln-10000 | 10,000 | 100,926 | ~5.4 s | ~700 MB |
| vuln-100000 | 100,000 | 1,003,677 | ~130 s | ~5.5 GB |

- **Time is still super-linear past 10k.** 10k→100k is 10× the files but
  **~24× the time** (5.4 s → ~130 s); per-file cost rose 0.54 ms → 1.3 ms.
  The Oct 16 fix (a35a33e) eliminated the O(R²) S3-correlation blowup, but a
  residual super-linear component remains — not yet profiled at this scale.
  An intermediate 20k-file probe (21 s, capped run) already showed the curve
  bending: 2× files → 3.9× time.
- **Memory is roughly linear:** 10× files → ~7.9× peak RSS (0.7 GB → 5.5 GB).
- **Operational edge:** on the 7.9 GB benchmark box, one run-3 attempt was
  OOM-killed (exit 137) at ~6 GB under transient memory pressure; the retry
  succeeded. At 100k files / 391 MB input, 2.0.0 needs roughly 6 GB of
  headroom — it fits, but barely, on an 8 GB machine.

## Verdict

Aegis did not break at 100,000 files: no crashes in completed runs, no
skipped files, no failed parses, fully deterministic output across 3 runs,
and severity/finding ratios identical to the 10k rung. Two honest headlines:

1. The engine scales to 1M findings, but the safety caps mean stock 2.0.0
   stops at 20k files / 256 MiB — large-repo users hit a wall, not a
   slowdown.
2. Past 10k files the time curve bends super-linear again (~24× time for
   10× files). The next engineering step is profiling at 100k, not guessing.

## Limitations (read before quoting numbers)

- Findings counts come from a **deliberately-vulnerable synthetic fixture**;
  they measure detection volume and determinism, not real-world recall.
- **False-positive rate at scale is unmeasured** — no ground-truth manifest
  exists for these fixtures (proposed: generator-produced expected-findings
  manifest + recall scorer).
- Manual accuracy spot-checks (40/40 TP historically) were done on smaller
  fixtures, not re-verified at 100k.
- Wall times are from a 2-CPU / 7.9 GB sandbox; absolute numbers will differ
  on other hardware, but the scaling shape should hold.
