# Benchmarks

Measured 2026-10-10 on this sandbox (linux/amd64). No superiority claims:
different tools ship different rule sets, so finding counts are reported
side by side, not ranked.

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
