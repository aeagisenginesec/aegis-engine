# 21 — vuln-4000 benchmark: extreme-pressure test of Aegis 2.0.0

Date: 2026-10-15. Engine: Aegis 2.0.0 (commit 9fb7304, colorized CLI).
Fixture: `~/workspace/vuln-4000/` — 4000 deliberately-vulnerable IaC files,
71,042 lines, generated deterministically by `~/workspace/vuln-1000-gen.py`
(seed=1000, VULN_SCALE=4; fixture files byte-identical across regenerations).
Same template pools as vuln-1000, 4× the file counts. All credentials fake.
Never apply against real accounts.

## Fixture composition

| Area | Files |
|---|---|
| terraform/aws/ | 1000 |
| terraform/azure/ | 800 |
| terraform/gcp/ | 600 |
| docker/ (Dockerfiles) | 400 |
| k8s/ (manifests) | 600 |
| cloudformation/ | 400 |
| compose/ | 200 |
| **Total** | **4000** (+ README) |

## Results (3 runs, `--format=json`)

| Run | Findings | Critical | High | Medium | Low | Files | Resources | Wall time | Peak RSS |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 39,543 | 2,010 | 11,137 | 14,821 | 11,575 | 4000/4000 | 6,198 | 5.06s | 314.6 MB |
| 2 | 39,543 | 2,010 | 11,137 | 14,821 | 11,575 | 4000/4000 | 6,198 | 6.41s | 312.2 MB |
| 3 | 39,543 | 2,010 | 11,137 | 14,821 | 11,575 | 4000/4000 | 6,198 | 5.02s | 322.1 MB |

- **Did it break? No.** All 4000 files parsed, 0 skipped, 0 failed.
  Exit code 1 (findings present) on all runs, as designed.
- **Determinism: byte-identical finding sets across all 3 runs.**
- **231 distinct rules fired** (same rule diversity as vuln-1000).
- **Accuracy spot-check: 8/8 true positives** (2 per severity, random),
  each verified against the file content. Same template pools as the
  vuln-1000 audit (24/24 true positives).

## Scaling honesty

| Fixture | Files | Findings | Wall time | Peak RSS |
|---|---|---|---|---|
| vuln-500 | 69 | 4,562 | 0.28s | 49 MB |
| vuln-1000 | 1000 | 9,719 | 0.47s | 84 MB |
| vuln-4000 | 4000 | 39,543 | ~5.5s | ~315 MB |

4× the files (vuln-1000 → vuln-4000) cost ~11× the time and ~3.8× the
memory. Scaling is **super-linear** — the engine holds together (no
failures, no skipped files, deterministic), but per-file cost rises with
corpus size. Likely contributors: JSON serialization of ~40k findings
with full remediation text, and GC pressure on a memory-constrained
7 GB box (~0 free during the runs). Linear scaling is **not** claimed;
this is the honest curve. Profiling the hot phase is future work.

## Critical spotlight (2,010 total)

Top critical rules mirror vuln-1000 at 4× scale: privileged containers,
IAM wildcard / privilege-escalation policies, public S3 exfiltration
paths, public GCS buckets, secrets in user_data / instance metadata,
internet-facing Cloud SQL.

## Notes

- Raw finding count is volume on a deliberately-vulnerable fixture, not
  precision. Precision measured separately (R4: F1 0.950, precision 1.000).
- Findings overlap by design: ~3.2 findings per distinct file:line on
  vuln-1000 (each rule is a distinct check with its own remediation).
