# vuln-10000 Extreme-Pressure Benchmark

**Date:** 2026-10-15
**Aegis:** 2.0.0 @ `f1b19b6` (engine code unchanged since the vuln-4000 run; only CLI/report/CI changes)
**Fixture:** `~/workspace/vuln-10000/` — 10,001 files (10,000 deliberately vulnerable + README), 177,760 lines, 40 MB
**Generator:** `~/workspace/vuln-1000-gen.py` with `VULN_SCALE=10` (seed 1000, byte-identical regeneration)

## Fixture distribution

| Type | Files |
|---|---|
| Terraform AWS | 2,500 |
| Terraform Azure | 2,000 |
| Terraform GCP | 1,500 |
| Dockerfiles | 1,000 |
| Kubernetes | 1,500 |
| CloudFormation | 1,000 |
| Docker Compose | 500 |
| **Total vulnerable** | **10,000** |

## Results (3 JSON runs)

| Run | Wall time | Peak RSS | Findings |
|---|---|---|---|
| 1 | 36.21 s | 638 MB | 100,926 |
| 2 | 36.03 s | 695 MB | 100,926 |
| 3 | 42.29 s | 803 MB | 100,926 |

**Findings breakdown:** 4,910 critical / 28,328 high / 38,210 medium / 29,478 low
**Resources:** 15,426 · **Distinct rules fired:** 231 · **Files parsed:** 10,000/10,000 (zero skipped, zero failed)

## Correctness

- **Determinism:** all 3 runs byte-identical finding sets (SHA-256 of rule/file/line/severity tuples).
- **Accuracy spot-check:** 8/8 true positives (2 per severity), each verified against its source file.

## Scaling analysis (honest)

| Fixture | Files | Findings | Wall time | Peak RSS |
|---|---|---|---|---|
| vuln-1000 | 1,000 | 9,719 | ~0.5 s | <90 MB |
| vuln-4000 | 4,000 | 39,543 | ~5.5 s | ~315 MB |
| vuln-10000 | 10,000 | 100,926 | ~38.2 s | ~712 MB |

- **Time is super-linear and worsening:** 4k→10k is 2.5× the files but **6.9× the time** (vs 4× files → 11× time on the previous rung).
- **Memory is roughly linear:** 2.5× files → 2.3× peak RSS.
- Suspected contributors remain JSON serialization with full remediation text and GC pressure — **not yet profiled or proven**. Profiling is the next engineering step before any optimization claim.

## Verdict

Aegis did not break at 10,000 files: no crashes, no skipped files, no failed parses, fully deterministic output, and spot-checked accuracy held. The scaling curve is the honest headline — time grows faster than the input, and that is now measured across three rungs, not guessed.
