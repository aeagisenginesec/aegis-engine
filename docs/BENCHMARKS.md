# Benchmarks

Measured 2026-10-10 on this sandbox (linux/amd64). No superiority claims:
different tools ship different rule sets, so finding counts are reported
side by side, not ranked.

## Benchmark authority (read first) — SOC #18, resolved 2026-11-25

**The standard.** Project-level detection is measured on **medium+
findings only**. A project counts as "found" iff it has ≥1 finding of
critical, high, or medium severity. Low/info findings are hygiene
(informational best practice, not vulnerabilities): they are counted
separately and never count as false positives. This is the same standard
the live `aegis quality-gate` uses (`internal/qualitygate/benchmark.go`:
"medium+ severity only") and the same standard
`benchmark/corpus-v2/score.py` uses. Any number quoted without this
standard is not comparable to the numbers below.

**The authorities.** There is one stored authority per corpus, and the
live gate is the authority for release claims:

| Claim | Authority | Regenerate with |
|-------|-----------|-----------------|
| Release-gate precision/recall (fpfn-bench, 500 projects) | Live `aegis quality-gate` — no stored file; the gate scans the current build every run | — |
| Phase-5 held-out corpus (200 projects, seed 999) | `benchmark/heldout_results.json` | `benchmark/run_heldout.py` (full, incl. Checkov) or `benchmark/final_benchmark.py` (Aegis-only refresh) |
| Rigorous held-out corpus (150 projects, seed 20261012) | `benchmark/rigorous/heldout2_results.json` | `benchmark/rigorous/heldout2_run.py` |
| Corpus-v2 (200 projects, dev + held-out) | Live `benchmark/corpus-v2/score.py --aegis-only` output — no stored results file | `benchmark/corpus-v2/score.py` |
| Per-rule FP analysis (phase-5 corpus) | `benchmark/fp_analysis.json` | `benchmark/analyze_fp.py` |

Every regenerated results file carries a `_meta` block (generator script,
standard, corpus, UTC timestamp, Aegis version, rule count, git commit).
A file without `_meta` predates this scheme: treat its numbers as a
historical snapshot, not as current.

**The guard.** `cmd/aegis/benchmark_authority_test.go` re-scans each
authority corpus with the current build (the CLI's own `scanFull` path,
medium+ counting) and fails if the stored aegis block disagrees; it also
fails if a deleted stale file reappears. If a rule change moves the
numbers, regenerate the file with its script — never hand-edit the
numbers. The test runs in `go test ./...` and therefore in CI.

**What happened (SOC #18).** `benchmark/detect_results.json` claimed
Aegis FP=60 (P=0.700) on the phase-5 corpus while
`benchmark/heldout_results.json` and the live gate claimed FP=0. Root
cause, established by re-running both standards against the current
build (1,148 rules): the two files used **different standards on
different binaries, and neither recorded either**.
`detect_results.json` was written pre-FP-fix (Oct 12, before commit
`0a5bb41`) under the old any-finding standard, when the clean fixtures
genuinely tripped high/medium rules — see the Oct-11
`heldout_severity_results.json` (aegis FP=60 including high) and
`docs/PHASE5_VALIDATION.md`. The Oct-12 fix made the any-standard FP
genuinely 0 at 698 rules (`fp_analysis.json` from that commit: zero
rules fired on any clean project). Later, two deliberate **low** rules
were added — AEGIS-AWS-742 (VPC without DNS hostnames) and AEGIS-AWS-852
(S3 with an AWS-managed key, no CMK) — which fire on all 60 clean
fixtures. So a fresh any-standard run today reproduces FP=60 again, but
composed 100% of low hygiene findings; under the medium+ standard the
current build gives TP=140 FP=0 FN=0 TN=60, P=R=F1=1.000 — the same
numbers `heldout_results.json` already claimed. No detection regression:
medium+ FP is 0 on the phase-5 corpus, on fpfn-bench (live gate), and
on corpus-v2 (dev F1 0.995, held-out F1 0.986, FP=0 both splits).
Resolution: `detect_results.json` and its generator `run_detect.py`
deleted (role subsumed by `heldout_results.json`);
`heldout_severity_results.json` deleted (Oct-11 pre-fix snapshot, no
generator, vacuous Checkov severity block);
`heldout_results.json` regenerated from the current build under medium+;
all generator scripts fixed to medium+ and to script-relative paths.
The rigorous corpus is different: its 52 "clean" projects are minimal
S3 setups never hardened against medium/high rules (012 no versioning,
206 no public access block, 443 no secure transport, 445 no access
logging), so its FP=52 is real under both standards and reproduces
unchanged on the current build — a corpus-label fact, not a rule bug,
and its report (`docs/RIGOROUS_BENCHMARK.md`) already says so.

**Historical snapshots (not authorities).** `final_showdown_raw.json`,
`showdown_1185_raw.json`, `perf_baseline.json`, `monitor_log.jsonl`,
`benchmark/rigorous/timing_results.json` and `vuln_rules.json` are
finding-count / timing snapshots from Oct 2026 runs (587–1,185 rules).
They make no precision/recall/FP claim and were left untouched.
`~/workspace/fpfn-bench/results.json` lives outside this repo and is an
Oct-2026 snapshot; the live gate never reads it.

## Method

- Corpus: `~/workspace/terraform/vuln-three-tier/` (41 resources, 9 `.tf` files).
- Each tool run 5×, wall-clock via `date +%s%N`; median reported.
- Aegis: `./aegis scan <dir> --format=json` (this repo's prebuilt binary).
- Trivy: `trivy config --format json` (checks bundle downloaded 2026-10-10).

## Pinned versions

| Tool  | Version | Source |
|-------|---------|--------|
| aegis | 0.1.0 (this repo) | `~/workspace/aegis-engine` |
| trivy | 0.74.0 | `~/workspace/bin/trivy` |

## Results

| Tool | Findings (all severities) | Critical | High | Medium | Low | Median wall time |
|------|---------------------------|----------|------|--------|-----|------------------|
| aegis | 20 → **27** | 2 → **3** | 12 → **16** | 6 → **8** | 0 | **0.038s → 0.011s** |
| trivy | 35 | 5 | 16 | 6 | 8 | **1.81s** |

Raw runs — aegis (optimized): 0.012/0.011/0.011/0.025/0.010s · trivy: 1.86/1.95/1.70/1.81/1.75s.

### 2026-10-10 optimization round

Two measured tracks, then re-benchmarked:
- **Coverage**: diffed our findings against Trivy's check-by-check and closed
  9 genuine gaps (AEGIS-AWS-201–209: internet-facing LBs, plain-HTTP
  listeners, IMDSv2, public-IP subnets, S3 access blocks, RDS/ElastiCache
  backups, VPC flow logs). Vuln-lab findings 20 → 27, all spot-verified.
- **Speed**: profiled (HCL tokenization 25.7%, GC pressure ~25%), then
  parallelized file parsing and rule evaluation with bounded worker pools
  (`runtime.NumCPU`). Lab 4.62ms → 3.09ms in-benchmark (33%); end-to-end
  0.038s → 0.011s. Output byte-identical, deterministic, race-clean.
- **Where we stand**: high-severity parity with Trivy on this corpus
  (16 vs 16). Remaining gap is mostly Trivy's 8 LOWs (low value) and 2
  criticals. Capabilities Trivy config doesn't bundle: attack-path
  correlation, validated auto-fix, plan-JSON input, localhost HTTP API.

## Honest caveats

- **Counts are not comparable.** Trivy's bundle ships hundreds of checks
  (including 8 LOWs aegis has no equivalent for); aegis ships 29 rules plus
  3 attack-path correlations trivy does not perform. Overlap on the core
  misconfigurations (open SGs, unencrypted RDS, public S3) is strong in both.
- **Speed is comparable.** Both scan the same files on the same machine.
  Aegis's single static binary with compiled-in rules starts and finishes
  faster than Trivy's Rego evaluation on this corpus (~45× here). This gap
  will narrow or invert on corpora where trivy's broader coverage matters
  more than raw speed.
- tfsec and checkov were not benchmarked: tfsec's binary in this sandbox
  does not report a version cleanly, and checkov is not installed.

## Reproduce

```bash
cd ~/workspace/aegis-engine
./aegis scan ~/workspace/terraform/vuln-three-tier --format=json
trivy config --format json ~/workspace/terraform/vuln-three-tier
```

### 2026-10-10 hardening round (rigorous benchmark)

Full methodology, all 30 raw runs, memory, and a finding-by-finding
TP/FP/FN analysis: `docs/BENCHMARK_RIGOROUS.md`.

| Tool | Findings | High-sev | Median (30 runs) | p95 | Peak RSS |
|------|----------|----------|------------------|-----|----------|
| aegis | **30** | **19** | **27.4ms** | 43.6ms | **12.1 MB** |
| trivy 0.74.0 | 35 | 16 | 2326ms | 4969ms | 217.1 MB |

- **Honest speedup: ~85× median** (the earlier 160× was measured on a
  less-loaded box; the rigorous number under memory pressure is 85×).
  Findings/sec: 985 vs 15.
- **False positives: 0** — all 30 aegis findings verified against source.
- **Two genuine gaps found and closed**: 002's `AppliesTo` missed the modern
  `aws_s3_bucket_acl` resource; 204's scope missed `aws_launch_template`.
  Both widened with tests. Lab: 27 → 30 findings, 16 → 19 high-severity.
- Large corpus (500 files / 3000 resources): aegis 1.05s vs trivy 27.9s (~27×).
