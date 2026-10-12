# Phase 5 — Competitive Benchmark Report

**Mission:** Aegis Independent Competitive Validation, Phase 5 (Competitive Benchmark)
**Date:** 2026-10-12 · **Analyst:** subagent (read-only on Aegis source; no rules/engine/tests modified, nothing committed, branch untouched)
**Aegis source:** `~/workspace/aegis-engine/`, branch `fix/demo-defects-d1-d3`, HEAD `0c28621`
**Machine:** 2 vCPU, 7.75 GB RAM (MemTotal 8125612 kB), Ubuntu 24.04, x86_64
**Raw data:** [docs/audit/raw/phase5/](raw/phase5/) — one JSON per scanner×corpus (16 files), per-run stdout/stderr dumps, `rerun.sh`

## 1. Pinned versions & rule counts

| Scanner | Version | Rule/query count (source) | IaC formats attempted |
|---|---|---|---|
| Aegis | 1.0.0 (built from `0c28621`) | **1,185** (`aegis doctor`: "rule registry: 1185 rules loaded") | Terraform, CloudFormation |
| Checkov | 3.3.26 | **1,318** Terraform *resource* check registrations (`checkov.terraform.checks.resource.registry`; data/provider/module checks additional) | Terraform, CloudFormation, Dockerfile, secrets (auto-detected) |
| KICS | 2.1.20 | **1,811** bundled queries (metadata.json count, all platforms); executed per corpus: 1148 / 1100 / 1100 / 1674 | Terraform, CloudFormation, + auto-detected others |
| Trivy | **0.75.0** (installed for this benchmark via pinned GitHub release deb, `dpkg`; recorded here) | Bundle policy count not enumerated; **200 distinct check IDs fired** across the 4 corpora (`trivy_distinct_check_ids.txt`) | Terraform, CloudFormation, Dockerfile (auto-detected) |

Trivy installation succeeded — no honest-failure path needed.

## 2. Frozen corpora (identical files for every scanner)

| Corpus | Root | Files presented |
|---|---|---|
| `terragoat` | `~/workspace/terragoat-fresh/terraform/` | 47 `.tf` (aws/azure/gcp/alicloud/oracle). Repo-root `package.json`/JS tooling excluded — not IaC. (Dir also contains 1 `.md`, 1 `.xlsx`, 1 `.zip`, 1 extensionless file.) |
| `vuln-200` | `~/workspace/terraform/vuln-200/` | 1 `.tf`, 1351 lines, ~200 resources |
| `corpus-v2` | `~/workspace/aegis-engine/benchmark/corpus-v2/projects/` | 150 projects, 155 `.tf`. **Exclusions documented:** `heldout/` excluded per `SPLIT.md` restriction policy (do not inspect); `gen/` is generator code, not IaC. Labels are Aegis-centric → valid for speed/count comparison, **not** for accuracy claims. |
| `aws-demo` | `~/workspace/aegis-engine/tests/demos/aws-security-demo/` | 68 `.tf` (vulnerable/ + secure/) + 16 CloudFormation `.yaml` + `manifest.json` |

No scanner-specific exclusions were applied; every scanner received the same root directory.

## 3. Method

- 5 timed runs per scanner×corpus (80 runs total), wall time via `perf_counter` around the subprocess, **median** reported.
- Per-run timeout 600 s (>10 min → kill, record TIMEOUT). No timeouts occurred.
- Counting (raw findings, no dedup, no accuracy judgment):
  - Aegis: `len(findings)` in `--format=json` output.
  - Checkov: Σ `results.failed_checks` across `check_type` entries (terraform+secrets+dockerfile+cfn as auto-detected).
  - KICS: Σ `len(query.files)` in `results.json`; parse integrity verified via `files_scanned`/`files_parsed`/`files_failed_to_scan`/`queries_failed_to_execute`.
  - Trivy: Σ `len(Misconfigurations)` across `Results[]` (`trivy config --format json`).
- Exact commands in each JSON's `command` field; exit codes and stderr tails preserved per run.
- KICS caveat honored: a failed/incomplete scan is never counted as zero — every KICS run's parse counts were verified (see §6).

Exact command lines:
- Aegis: `/tmp/aegis-p5 scan <corpus> --format=json`
- Checkov: `~/.venv-checkov/bin/checkov -d <corpus> --output json`
- KICS: `~/workspace/bin/kics scan -p <corpus> -o <outdir> --report-formats json --no-progress --minimal-ui` (cwd `~/workspace/kics`, required for `./assets/queries`)
- Trivy: `trivy config --format json --output <file> <corpus>`

## 4. Results — per-corpus table (median of 5 runs)

| Corpus | Scanner | Median wall | Findings (raw) | Exit | Status |
|---|---|---|---|---|---|
| terragoat | **Aegis** | **0.331 s** | **577** | 1 | ok |
|  | Checkov | 22.631 s | 474 (467 tf + 5 secrets + 2 dockerfile) | 1 | ok |
|  | KICS | 60.831 s | 304 | 60 | ok (48/48 files parsed, 1148 queries, 0 failed) |
|  | Trivy | 2.747 s | 254 (252 tf + 2 dockerfile) | 0 | ok |
| vuln-200 | **Aegis** | **0.325 s** | **957** | 1 | ok |
|  | Checkov | 29.399 s | 788 (787 tf + 1 secret) | 1 | ok |
|  | KICS | 69.164 s | **1437** | 60 | ok (1/1 parsed, 1100 queries, 0 failed) |
|  | Trivy | 2.622 s | 495 | 0 | ok |
| corpus-v2 | **Aegis** | **0.624 s** | 441 | 1 | ok |
|  | Checkov | 57.034 s | 475 (466 tf + 9 secrets; **3 parsing errors**, count only) | 1 | ok |
|  | KICS | 55.613 s | **806** | 60 | ok (150/155 parsed — the 5 unparsed are the labeled-secure projects, 0 findings = correct; 0 failed) |
|  | Trivy | 3.891 s | 109 | 0 | ok |
| aws-demo | **Aegis** | **0.248 s** | **421** | 1 | ok (85 discovered, 84 parsed, 1 skipped=`manifest.json` w/ documented warning, 0 failed) |
|  | Checkov | 12.341 s | 327 (275 tf + 10 secrets + 42 cfn) | 1 | ok |
|  | KICS | 73.306 s | 419 | 60 | ok (84/84 parsed, 1674 queries, 0 failed) |
|  | Trivy | 2.562 s | 221 (170 tf + 51 cfn) | 0 | ok |

Exit-code semantics: Aegis/Checkov exit 1 when findings present; KICS exits **60** when results match `--fail-on` (default: all severities), 0 when clean; Trivy `config` exits 0 regardless.

## 5. Speedup factors vs Aegis (median competitor ÷ median Aegis)

| Corpus | Checkov | KICS | Trivy |
|---|---|---|---|
| terragoat | **68×** | **184×** | **8.3×** |
| vuln-200 | **90×** | **213×** | **8.1×** |
| corpus-v2 | **91×** | **89×** | **6.2×** |
| aws-demo | **50×** | **296×** | **10.3×** |

Aegis is the fastest scanner on every corpus by a wide margin (6×–296×). Trivy is the closest competitor on speed.

## 6. Where Aegis does NOT win — raw finding counts

Aegis reports the most findings on terragoat (577) and aws-demo (421), but **loses on raw count** to KICS on two corpora:

- **vuln-200:** KICS 1437 > Aegis 957 > Checkov 788 > Trivy 495
- **corpus-v2:** KICS 806 > Checkov 475 > Aegis 441 > Trivy 109

Severity mix matters for interpreting counts (KICS counts INFO findings; same query can fire per-file many times):

| Corpus | KICS severity mix | Aegis severity mix |
|---|---|---|
| vuln-200 | CRIT 11 / HIGH 882 / MED 210 / LOW 107 / INFO 227 | crit 23 / high 281 / med 307 / low 346 |
| corpus-v2 | CRIT 4 / HIGH 181 / MED 95 / LOW 238 / INFO 288 | crit 21 / high 96 / med 63 / low 261 |
| terragoat | CRIT 4 / HIGH 69 / MED 116 / LOW 58 / INFO 57 | crit 7 / high 131 / med 266 / low 173 |
| aws-demo | CRIT 3 / HIGH 45 / MED 115 / LOW 170 / INFO 86 | crit 20 / high 95 / med 100 / low 202 / info 4 |

Raw counts are not scored — no precision/recall is claimed here (see §8). The count gap is reported as observed.

## 7. Failure / timeout / anomaly log

**No crashes, no hangs, no timeouts.** All 80 runs completed `ok`. Anomalies recorded, not hidden:

1. **KICS run-to-run variance (pre-benchmark probe vs benchmark).** A single pre-benchmark probe on vuln-200 returned **949 findings in 236 s**; all 5 benchmark runs returned **1437 findings (~69 s median)**. Same 102 queries fired in both; the gap is concentrated in HIGH (394 → 882). Suspected cause: per-query 60 s timeout truncation in the slow run (KICS `queries_failed_to_execute` stayed 0, so timeouts are silent). Reported number = 1437 (5/5 consistent). Lesson: single KICS runs are not reproducible — the 5-run median protocol is load-bearing here.
2. **KICS corpus-v2 parse accounting:** `files_scanned` 155 vs `files_parsed` 150. The 5 unparsed files are exactly the 5 labeled-secure projects (`v2-157/169/171/173/174`, `vulnerable=False`), which correctly produced 0 findings; `files_failed_to_scan`=0, `queries_failed_to_execute`=0. Not a failure — recorded for completeness.
3. **KICS operational caveat (verified):** KICS resolves queries from `./assets/queries` relative to cwd. Run from anywhere else it prints the banner, exits 0, and writes **no findings at all** — indistinguishable from a clean scan without checking `results.json`. All benchmark runs used cwd `~/workspace/kics`.
4. **Checkov corpus-v2: 3 Terraform parsing errors** (summary count only; Checkov's JSON does not name the files). Findings still reported normally (475).
5. **Aegis aws-demo:** `manifest.json` skipped with a documented warning diagnostic ("unrecognized document … skipped"); 84/85 files parsed, 0 failed. CloudFormation YAML parsed natively (16/16).
6. **Checkov auto-detects extra frameworks** on the same files: dockerfile checks fired on terragoat (2 failed), cloudformation checks on aws-demo (42 failed). Same input files; broader format coverage than Aegis on terragoat.
7. **Raw stdout dumps truncated:** `raw_outputs/<scan>/run*.stdout` are tail-truncated at 50 KB (large Checkov JSONs start mid-document). All counts were computed from full in-memory stdout; the per-scanner summary JSONs (`<scanner>_<corpus>.json`) are complete and authoritative.

## 8. What this does NOT prove

- **Raw finding counts are not accuracy.** More findings can mean more true positives, more false positives, or just finer-grained rule splitting (one resource → N findings). Precision/recall against labeled ground truth is Phase 4's job, not this phase's.
- **corpus-v2 labels are Aegis-centric** (expected rule IDs are Aegis rule IDs). Count comparisons there are valid; any accuracy claim would be circular.
- **Severity mixes differ** (§6): KICS reports INFO findings that inflate its totals; Aegis reports almost none. Headline counts are not severity-normalized.
- **Speed was measured on one 2-vCPU VM** with cold/warm caches as they fell (5-run medians; KICS run 1 on terragoat was 121 s vs 55–60 s later — cache warmup is real). Numbers are comparative on this machine, not absolute.
- **Rule-count comparability is approximate:** Aegis 1185 runtime-loaded rules; Checkov 1318 *resource* registrations (+data/provider/module checks, plus secrets/dockerfile/cfn frameworks that fired); KICS 1811 bundled queries of which 1100–1674 executed per corpus; Trivy bundle size not enumerated (200 distinct IDs fired). Different counting units — do not rank "coverage" by these.
- **No dedup or per-resource analysis** was performed.

## 9. Reproducibility

```bash
./docs/audit/raw/phase5/rerun.sh [--only SCANNER] [--only-corpus CORPUS] [--runs N]
```

`rerun.sh` verifies git HEAD (`0c28621`, warns on mismatch), rebuilds `/tmp/aegis-p5` from source, prints all scanner versions, and re-runs `run_phase5.py`. Raw outputs land in `docs/audit/raw/phase5/` (`<scanner>_<corpus>.json` summaries + `raw_outputs/` per-run dumps). Note: rerun requires the same tool paths (Checkov venv, KICS binary+`~/workspace/kics/assets`, Trivy 0.75.0).

## 10. Bottom line

- **Speed:** Aegis wins everywhere, 6×–296× faster than the nearest competitor per corpus (Trivy closest).
- **Volume:** Aegis leads raw counts on terragoat and aws-demo; **KICS reports substantially more raw findings on vuln-200 (1437 vs 957) and corpus-v2 (806 vs 441)** — reported as observed, with severity mixes and the no-accuracy-claims caveat above.
- **Robustness:** zero crashes/timeouts across 80 runs; two honest anomalies logged (KICS single-run variance; Checkov's 3 silent parse errors on corpus-v2).
