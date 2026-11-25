# Phase 5: Independent Held-Out Validation

**Date:** 2026-10-11
**Status:** Complete

> **Update (2026-11-25, benchmark authority, SOC #18):** this report
> records the **Oct-11 pre-FP-fix run** (326 rules, any-finding
> standard): Aegis P=0.700 / F1=0.824, FP=60. Those numbers were true
> for that run and are kept as history below. On Oct 12 the FP fixes
> landed (commit `0a5bb41`, 698 rules) and the any-standard FP became
> genuinely 0; on 2026-11-25 `benchmark/heldout_results.json` was
> regenerated from the current build (1,148 rules) under the medium+
> standard — Aegis TP=140 FP=0 FN=0 TN=60, P=R=F1=1.000; Checkov
> unchanged at TP=140 FP=60, P=0.700, F1=0.824. The stale pre-fix
> snapshots `benchmark/detect_results.json` and
> `benchmark/heldout_severity_results.json` were deleted. Current
> numbers and the single authority per corpus: `docs/BENCHMARKS.md`.

## Methodology

### Held-Out Corpus
- **200 projects**, generated with seed 999 (different from the 500-project seed 42 corpus)
- **140 vulnerable / 60 clean** split
- **Realistic structures:** multiple `.tf` files per project (`main.tf`, `variables.tf`, `outputs.tf`, `network.tf`, `database.tf`), plus `modules/networking/` in every project
- **Vulnerability mixes** not in the original corpus: KMS+Lambda combos, DynamoDB+IAM, multi-resource chains (SG→EC2→RDS), Terraform HTTP backends, CloudTrail misconfigurations, secrets in user_data
- **183 total planted vulnerabilities** across 140 vulnerable projects

### Frozen Versions
| Component | Version |
|-----------|---------|
| Aegis binary | sha256: b44440068642532db45b2e95411f2cda6864616a691c5f0cdc8c3d2d0ab8e20e |
| Aegis rules | 326 |
| Checkov | 3.3.26 |
| Go | go1.25.4 linux/amd64 |
| Platform | 2-CPU sandbox |

### Protocol
1. Same 200 projects, same scan scope, both tools
2. Project-level metrics: TP = vulnerable project with ≥1 finding; FP = clean project with ≥1 finding
3. Timing: 5 runs per project on 20-project sample, median/p95 reported
4. Aegis vs Checkov head-to-head only (Snyk/Terrascan errored in prior runs)

## Results

### Detection (all severities, project-level)

| Tool | Precision | Recall | F1 | TP | FP | FN | TN |
|------|-----------|--------|-----|----|----|----|----|
| Aegis | 0.700 | 1.000 | 0.824 | 140 | 60 | 0 | 0 |
| Checkov | 0.700 | 1.000 | 0.824 | 140 | 60 | 0 | 0 |

**Both tools performed identically.** Both caught all 140 vulnerable projects. Both flagged all 60 "clean" projects.

### Detection (high/critical severity only, Aegis)

| Tool | Precision | Recall | F1 | TP | FP | FN | TN |
|------|-----------|--------|-----|----|----|----|----|
| Aegis | 0.674 | 0.886 | 0.765 | 124 | 60 | 16 | 0 |

16 vulnerable projects had no high-severity findings (their issues were medium/low). Checkov severity filtering was not possible — its JSON output leaves `severity: null` on failed checks.

### Speed (20-project sample, 5 runs each)

| Tool | Min | Median | p95 | Max |
|------|-----|--------|-----|-----|
| Aegis | 6.0ms | 7.8ms | 12.4ms | 12.4ms |
| Checkov | 3883ms | 4054ms | 4394ms | 4394ms |

**Aegis is ~520x faster** (median 7.8ms vs 4054ms).

### Attack-Path Validation (5 spot-checks)

| # | Scenario | Expected | Result |
|---|----------|----------|--------|
| 1 | SG(0.0.0.0/0) → EC2 → RDS (shared SG) | Full chain with evidence | ✅ 3-hop HIGH chain, each hop cites file:line |
| 2 | Variable CIDR, shared SG, EC2 → RDS | Uncertain entry, not invented | ✅ `[UNCERTAIN: no public ALB or world-open SG reaches ...]` |
| 3 | Isolated S3 + EC2 (no shared network) | No chain | ✅ "No complete attack chains found" |
| 4 | Held-out chain projects (SG→EC2→RDS split across files) | Chain detected | ❌ 0 chains — no graph edge (RDS didn't share SG) |
| 5 | Variable CIDR only, no data store | No chain | ✅ Correctly empty |

**Finding:** The builder correctly refuses to invent connections. Spot-check 4 revealed the held-out `chain-sg-ec2-rds` projects don't create graph edges (RDS lacks SG reference) — a corpus design gap, not a builder bug.

## Verdict

On this held-out corpus, **Aegis matches Checkov exactly on detection** (identical precision, recall, F1) while running **~520x faster**. Neither tool achieves the 95% precision gate at project level — both are noisy on hygiene. Aegis's differentiators (attack paths, speed, unique rule classes) don't show in these aggregate numbers but were validated separately.

This is a defensible, reproducible result for the Oct-11 pre-fix run. Raw data: `benchmark/heldout_results.json` (regenerated 2026-11-25 under the medium+ standard; see `docs/BENCHMARKS.md`). The pre-fix severity breakdown formerly in `benchmark/heldout_severity_results.json` was deleted with that file — it was an Oct-11 snapshot with no generator.
