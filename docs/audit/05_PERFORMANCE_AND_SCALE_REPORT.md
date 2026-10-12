# Phase 6 — Performance and Scalability Report

**Mission:** Aegis Independent Competitive Validation, Phase 6 (Performance and Scalability)
**Date:** 2026-10-12
**Binary:** `/tmp/aegis-p6` built from `~/workspace/aegis-engine`, branch
`fix/demo-defects-d1-d3`, HEAD `0c28621` (`aegis 1.0.0`, **1185 rules** loaded per `aegis doctor`)
**Machine:** 2 vCPU, 7 GB RAM, Linux 7.0.0-39-generic, Go 1.25.4, `GOMAXPROCS=2` (default)
**Source discipline:** read-only — no repo files modified, nothing committed, no branch switch.

## 1. Methodology

### 1.1 Corpora

| Corpus | Files | Content | Size on disk |
|---|---|---|---|
| `small` | 10 | First 10 files of `tests/demos/aws-security-demo/vulnerable/` (real) | 40 KB |
| `medium` | 200 | All 155 `benchmark/corpus-v2/projects/**/*.tf` (real, incl. 3 nested in `v2-131`) + 24 `vulnerable/11–34` + 21 `secure/01–21` demo files (real) | 744 KB |
| `large` | 2,000 | **Generated** — `docs/audit/raw/phase6/gen_large.py`, seed `20261012` (deterministic; SHA-256 manifest at `/tmp/p6/large.MANIFEST.sha256`). 10 AWS resource templates (s3, sg, rds, iam, kms, cloudtrail, ec2, secretsmanager, sns, ebs) × secure/vulnerable variants (~60% vulnerable), 1–3 resources/file, unique names per file, ~4.2 KB/file | 8.5 MiB |
| `huge-under` | 1 | **Generated** — `docs/audit/raw/phase6/gen_huge.py`, single 9.50 MiB file (just under the 10 MiB default `--max-file-size`) | 9.5 MiB |
| `huge-over` | 1 | **Generated** — single 10.60 MiB file (just over the cap) | 10.6 MiB |

### 1.2 Timing protocol (matches quality-gate methodology)

- **11 timed runs** per corpus (`small`, `medium`, `large`); **5 runs** for the huge-file edge cases
  (each run costs 36–84 s; 11 would add no information).
- Command: `aegis scan <dir> --format=text` (the default user path), stdout piped and fully
  consumed, findings/resources parsed from the `resources: R, findings: F` summary line.
- **Cold vs warm:** `echo 3 > /proc/sys/vm/drop_caches` was **denied** (read-only `/proc` in this
  sandbox), so all runs are OS-page-cache **warm-start**. Run 1 of each target is labeled `cold`
  (first exec of the binary — process cold-start); runs 2..N are `warm`. There is no meaningful
  cold/warm delta beyond noise (see §2).
- **Peak RSS:** `/usr/bin/time` is not installed on this box. Instead the harness (`run_perf.py`)
  fork/execs the scan and reads `os.wait4()` `ru_maxrss` — the same quantity GNU `time -v`
  reports as "Maximum resident set size" (kilobytes on Linux).
  - *Correction applied:* `ru_maxrss` also captures the instant before `exec`, when the child
    still shares the parent's heap. After the `huge-under` runs the parent held ~265 MB of
    captured output, contaminating the `huge-over` RSS readings (259 MB for an empty scan).
    Those 5 values were re-measured in a fresh parent (13.0–13.5 MB) and patched; the artifact
    is documented here rather than hidden.
- **Completeness:** one `--format=json` run per corpus; `scan_completeness`
  (`files_discovered/parsed/skipped/failed`) attached to every CSV row (verified run-invariant).
- **Stage breakdown:** no repo instrumentation (read-only constraint). A `/tmp`-only Go program
  (`docs/audit/raw/phase6/stage_harness/stagebreak_main.go`, built with
  `module aegis/stagebreak` + `replace aegis => …/aegis-engine` to satisfy the `internal/`
  visibility rule) replicates the production pipeline — `discovery.Discover` →
  concurrent parse (`NumCPU` workers, same as `parseFilesConcurrent`) → `semantics`
  merge/resolve/expand → `RegistryFor("all").Run` + `EnrichCompliance` → `report.WriteJSON`
  to discard — timing each stage. Medians over 3–5 iterations. Caveat: the report stage
  measures JSON-to-discard; the CLI timing runs use the heavier **text** renderer.
- **Engine isolation:** `rulebreak_main.go` parses `large` once, then times
  `registry.Run` on resource prefixes (250 → 7373) with a warm registry, plus
  `EnrichCompliance` separately; `freshrun_main.go` times fresh-registry `Run`.

## 2. End-to-end results (CLI, `--format=text`)

| Corpus | Files | min | median | p95 | max | run 1 ("cold") | warm median | Peak RSS | Findings | Resources |
|---|---|---|---|---|---|---|---|---|---|---|
| small | 10 | 44.2 ms | **89.8 ms** | 234.6 ms | 291.2 ms | 105.3 ms | 87.0 ms | 15.6 MiB | 56 | 11 |
| medium | 200 | 490.1 ms | **747.7 ms** | 1,860.3 ms | 2,551.5 ms | 631.4 ms | 764.5 ms | 22.9 MiB | 706 | 464 |
| large | 2,000 | 15,176.8 ms | **17,657.9 ms** | 19,443.2 ms | 19,515.2 ms | 18,241.2 ms | 17,603.8 ms | 112.8 MiB | 17,126 | 7,373 |
| huge-under | 1 (9.5 MiB) | 36,498.4 ms | **47,680.8 ms** | 48,137.6 ms | 83,611.1 ms | 83,611.1 ms | 42,143.1 ms | 875.7 MiB | 275,502 | 44,080 |
| huge-over | 1 (10.6 MiB) | 82.6 ms | **92.3 ms** | 96.4 ms | 102.9 ms | 83.3 ms | 94.3 ms | ~13.2 MiB | 0 | 0 |

Notes:

- **Variance is high** on this 2-vCPU sandbox (sibling workloads active during the runs):
  small spans 44→291 ms, medium 490→2,552 ms. Medians are the robust estimator; the raw
  11-run series is in `perf.csv`.
- **No cold-start penalty** is visible: run 1 sits inside the warm distribution at every scale
  (medium run 1 was even *faster* than the warm median). With warm page cache and a ~50–90 ms
  process-startup floor, first-run cost is negligible next to scan cost.
- The quality-gate reference (median 18.1 ms on vuln-200, threshold ≤ 500 ms) is **not directly
  comparable**: the in-repo Go benchmarks (`internal/perf`) are stubs that only time
  `rules.DefaultRegistry()` construction, and the 18.1 ms figure was CLI-measured on a
  different, tiny-file corpus. On realistic multi-resource files, 200 files cost 748 ms here.

## 3. Scan completeness — every file accounted for

| Corpus | Discovered | Parsed | Skipped | Failed | Sum check |
|---|---|---|---|---|---|
| small | 10 | 10 | 0 | 0 | ✅ 10 = 10 |
| medium | 200 | 199 | 1 | 0 | ✅ 200 = 199+1 |
| large | 2,000 | 2,000 | 0 | 0 | ✅ |
| huge-under | 1 | 1 | 0 | 0 | ✅ |
| huge-over | 0 | 0 | 0 | 0 | ✅ (vacuous — see finding 2) |

**Finding 1 — warning-level skip silently drops a file's resources (medium).**
`v2-134__main.tf` is reported `skipped` with reason
`terraform: aws_db_instance.dbs uses "for_each" with an unresolvable expression; analyzed as a
single instance` — yet the reason text says it was *analyzed*. In `scanFull`, any warning
diagnostic flips the file to `skipped` and `continue`s past resource collection, so the file's
resources never reach the rule engine (CLI: 464 resources / 706 findings vs 465 / 722 when the
file is force-included). The accounting adds up, but a user reading "skipped … analyzed as a
single instance" would reasonably believe the file *was* scanned. Recommend either scanning the
degraded single instance or rewording the status.

**Finding 2 — over-cap files vanish without a trace (huge-over).**
A 10.6 MiB file with the default 10 MiB `--max-file-size` is **not discovered at all**
(`files_discovered: 0`, no diagnostic, no completeness entry) — despite `--help` promising
"files larger than this are skipped with a diagnostic". With `--max-file-size 12582912` the
file is discovered but then *fails* with `terraform: … file exceeds 10 MiB limit`: the
terraform adapter has a second, **non-overridable 10 MiB hard cap**. So the flag raises the
discovery cap but cannot raise the parser cap, and at defaults the drop is silent. Recommend
emitting a discovery-level skip diagnostic naming the file and the cap.

**Minor schema note:** when `files_discovered` is 0, `scan_completeness` omits the `files`
array entirely (consumers should not assume the key exists).

## 4. Pipeline-stage breakdown (stage-harness medians, ms)

| Target | Files | Resources | Findings | Discovery | Parse | Semantics | Rules | Report (JSON) | Σ stages | CLI median |
|---|---|---|---|---|---|---|---|---|---|---|
| small | 10 | 11 | 56 | 0.10 | 5.74 | 0.05 | 13.25 | 0.87 | 20.0 | 89.8 |
| n100¹ | 100 | 360 | 795 | 0.47 | 176.0 | 2.60 | 52.8 | 15.3 | 247 | — |
| medium | 200 | 465 | 722 | 4.73 | 191.4 | 13.69 | 176.6 | 59.1 | 445.5 | 747.7 |
| n250¹ | 250 | 899 | 2,047 | 7.36 | 479.7 | 8.03 | 158.0 | 131.5 | 784.5 | — |
| n500¹ | 500 | 1,805 | 4,094 | 2.81 | 385.2 | 21.79 | 252.2 | 95.6 | 757.6 | — |
| n1000¹ | 1,000 | 3,658 | 8,450 | 5.81 | 1,176.0 | 31.41 | 975.7 | 164.3 | 2,353.2 | — |
| large | 2,000 | 7,373 | 17,126 | 23.72 | 4,801.0 | 189.37 | 8,269.3 | 985.2 | 14,268.6 | 17,657.9 |
| huge-under | 1 | 44,080 | 275,502 | 0.08 | 7,401.7 | 559.09 | 28,854.4 | 6,184.8 | 43,000.0 | 47,680.8 |

¹ First-N-files subsets of `large`, for the scaling curve.

- The CLI-vs-harness gap (70 ms → 300 ms → 3.4 s) grows with finding count: it is process
  startup plus the **text report renderer** (the harness measures JSON-to-discard). Text
  rendering of 17k findings costs on the order of 0.2 ms/finding.
- At 2,000 files the **rule engine is 58% of pipeline time**; parse is 34%. Discovery and
  semantics are minor at file-count scale (semantics matters more per-module; see §5).
- `huge-under` shows the single-file pathologies: parse is serial (7.4 s, no worker
  parallelism for one file) and the engine grinds on 44k resources (28.9 s).

## 5. Throughput and scaling — it is not linear

Throughput at median wall time:

| Corpus | files/s | resources/s |
|---|---|---|
| small (10) | 111 | 122 |
| medium (200) | 268 | 621 |
| large (2,000) | 113 | 418 |

Log-log least-squares exponents `time ∝ files^b`:

| Scope | Exponent b | R² | Reading |
|---|---|---|---|
| End-to-end CLI (10/200/2000) | **0.98** | 0.96 | *Misleading* — averages a startup-dominated sublinear bottom decade with a superlinear top decade |
| End-to-end, top decade only (200→2000) | **1.37** | — | 10× files → 23.6× time |
| Discovery | 0.98 | 0.85 | linear ✅ |
| Parse | 1.18 | 0.96 | mildly superlinear |
| Semantics | 1.47 | 0.97 | superlinear (cross-module merge/resolve) |
| Rules (cold registry, in-pipeline) | 1.12 | 0.88 | noisy fit; see isolated measurement |
| Report (JSON) | 1.25 | 0.95 | superlinear in files+findings |

**Isolated rule-engine scaling** (warm registry, `registry.Run` only, resources 250→7373):

| Resources | Run (ms) | EnrichCompliance (ms) | Segment exponent |
|---|---|---|---|
| 250 | 25.2 | 0.04 | — |
| 500 | 25.2 | 0.07 | 0.00 |
| 1,000 | 58.2 | 0.12 | 1.21 |
| 2,000 | 136.5 | 0.26 | 1.23 |
| 4,000 | 411.7 | 0.57 | 1.59 |
| 7,373 | 1,297.6 | 0.83 | **1.88** |

Overall fit b = 1.21, but the **segment exponent accelerates 1.2 → 1.6 → 1.9**: a quadratic
component in the engine dominates at thousands of resources (consistent with per-resource
rules doing cross-resource correlation). `EnrichCompliance` is negligible (< 1 ms at 17k
findings) — not the culprit. A **fresh registry's first `Run`** costs ~3.2× the warmed one
(3.8–4.5 s vs 1.3 s at 7,373 resources): one-time cache construction the CLI pays on every
invocation.

**Bottom line:** end-to-end scaling is effectively linear only below ~200 files. From 200 to
2,000 files the exponent is ~1.4; the rule engine alone approaches quadratic (b → 1.9) past
~4,000 resources. A 20,000-file repo would not cost 10× the 2,000-file scan — the current
trajectory says roughly 25–35×. This is the phase's main scalability risk, and it lives in
the rule engine, not the parser.

## 6. Regression check — speed did not cost detection

Same binary at every scale, so this is a completeness/determinism check:

1. **Determinism:** finding counts identical across all 11 runs at every scale
   (small: 56, medium: 706, large: 17,126, huge-under: 275,502 — single distinct value each).
2. **No cross-file interference:** 5 randomly chosen `large` files scanned standalone produce
   byte-identical finding multisets (rule_id + severity + resource) to their in-corpus
   results — 5/5 match (5, 8, 2, 16, 8 findings).
3. **Subset rate check:** first 100 files of `large` scanned standalone → 795 findings,
   exactly the in-corpus sum for those files. Corpus-wide rate 8.56 findings/file is stable;
   detection does not degrade with corpus size.
4. **Fixed-ruleset expectation:** all scans used `--rules=all` (1,185 rules) from the same
   binary; per-file finding identity (check 2) confirms the engine evaluates every resource
   identically regardless of corpus size.

Caveat: the medium corpus's `v2-134` warning-skip (§3, Finding 1) means one file's resources
are excluded from detection — a completeness gap, not a scaling regression.

## 7. Honest limits

- **2-vCPU sandbox, not production hardware.** Noisy neighbors produced wide run-to-run
  variance (small: 44–291 ms). All conclusions use medians; raw series in `perf.csv`.
- **Warm OS page cache throughout** (`drop_caches` denied). True cold-cache numbers
  (e.g., first scan after reboot on spinning disk) were not measured.
- **`/usr/bin/time` absent** — peak RSS via `os.wait4()` `ru_maxrss` (same quantity), with
  the fork-inheritance artifact documented and corrected in §1.2.
- **Large corpus is synthetic** (seeded generator, realistic templates, deterministic), not a
  real 2,000-file repo. Module-heavy real repos would stress `semantics` (b = 1.47) more
  than this corpus does.
- **Stage harness replicates but is not the CLI path** (report stage is JSON-to-discard;
  the CLI's text renderer is heavier — the 3.4 s CLI-vs-harness gap at `large`).
- **No profiling was done** (read-only constraint respected: no instrumentation added to
  the repo). The quadratic engine component is characterized black-box; the specific
  rule(s) responsible were not isolated.
- **In-repo Go perf benchmarks are stubs** (`BenchmarkFullScan` times registry construction,
  not a scan), so the 18.1 ms vuln-200 quality-gate figure could not be reproduced or
  directly compared.

## 8. Raw artifacts

All under `docs/audit/raw/phase6/`:

- `perf.csv` — 43 rows: `repo_size,run,wall_ms,rss_kb,findings,resources,files_discovered,parsed,skipped,failed,cold_warm`
- `stage_breakdown.csv` — stage-harness medians per target/subset
- `engine_scaling.csv` — isolated `registry.Run` / `EnrichCompliance` scaling points
- `gen_large.py` — 2,000-file corpus generator (seed 20261012)
- `gen_huge.py` — single-huge-file generator
- `run_perf.py` — timing harness (fork/exec + `wait4` wall/RSS, JSON completeness probe)
- `analyze.py` — summary stats, throughput, log-log exponent fits
- `stage_harness/` — `stagebreak_main.go`, `rulebreak_main.go`, `freshrun_main.go`,
  `go.mod.template` (build with `module aegis/stagebreak` + `replace aegis => <repo>`,
  `GOPROXY=off GOFLAGS=-mod=mod`)
- Test corpora lived in `/tmp/p6/` (ephemeral); large-corpus SHA-256 manifest was at
  `/tmp/p6/large.MANIFEST.sha256` (regenerable byte-identically via `gen_large.py`).

## 9. Recommendations for the parent mission

1. **Investigate the rule engine's superlinear component** (b → 1.9 past ~4k resources)
   before claiming production-scale readiness — likely a cross-resource correlation in one
   or more rules; a black-box bisect (rule packs on/off at 4k+ resources) would isolate it
   without touching source.
2. **Fix the two completeness gaps**: emit a discovery-level skip diagnostic for
   over-cap files (currently silent), and reconcile the `v2-134` "skipped yet analyzed"
   warning path (either scan the degraded instance or fix the status wording).
3. **Align the quality-gate perf story**: the in-repo benchmarks are stubs and the 18.1 ms
   vuln-200 figure doesn't transfer to realistic corpora (748 ms for 200 real files here).
   Consider gating on a realistic fixed corpus with the CLI harness from this phase.
4. **Memory:** 113 MiB peak at 2,000 files / 876 MiB at one 9.5 MiB file are comfortable
   for CI runners, but the text renderer holds the full finding set in memory — streaming
   output would flatten the worst case.
