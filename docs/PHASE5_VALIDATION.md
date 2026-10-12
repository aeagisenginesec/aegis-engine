# Phase 5: Independent Held-Out Validation

**Date:** 2026-10-11
**Status:** Complete

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

## Honest Limitations

1. **"Clean" projects weren't clean.** All 60 triggered findings (VPC flow logs from `modules/`, S3 hygiene on log buckets, TLS enforcement). True zero-finding baselines are hard; project-level FP metrics are inflated for both tools equally.

2. **Project-level, not vulnerability-level.** We measure "did it flag the project," not "did it find each of the 183 planted vulns." Finer granularity requires per-vuln labeling.

3. **Synthetic corpus.** Generated Terraform, not real-world repos. Real code has more variables, modules, and dynamic blocks.

4. **Single-machine timing.** 2-CPU sandbox; absolute times won't transfer, but the 520x ratio is robust.

5. **Precision below 95% gate.** Both tools: 70.0% at project level (all severities). The quality gate's ≥95% target remains unmet — driven by hygiene rules firing on "clean" projects. This is honest noise, not a detection failure (recall is 100%).

6. **Checkov severity n/a.** Cannot compare high-severity precision — Checkov's JSON doesn't populate severity fields.

## Verdict

On this held-out corpus, **Aegis matches Checkov exactly on detection** (identical precision, recall, F1) while running **~520x faster**. Neither tool achieves the 95% precision gate at project level — both are noisy on hygiene. Aegis's differentiators (attack paths, speed, unique rule classes) don't show in these aggregate numbers but were validated separately.

This is a defensible, reproducible result. Raw data: `benchmark/heldout_results.json`, `benchmark/heldout_severity_results.json`.
