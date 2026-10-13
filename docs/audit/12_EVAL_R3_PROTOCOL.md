# Round-3 Evaluation Protocol (PRE-REGISTERED)

**Date:** 2026-10-13
**Status:** FROZEN before execution. No changes after results observed.
**Candidate:** `mission/pulumi-recovery` branch (Pulumi fix + hygiene audit, no
detection changes except the Pulumi adapter coverage fix).
**Supersedes:** Round-2 protocol for the Pulumi-coverage question only. The
three-part win condition is UNCHANGED.

## Win condition (unchanged from round 2)

Aegis wins iff ALL THREE hold vs Checkov, KICS, and Trivy:
- (a) **Highest F1** (firm concepts, adjudicated)
- (b) **Lowest FP rate** (adjudicated)
- (c) **Fastest** (median per-project scan time, 2× decision threshold)

No partial credit. No threshold changes after seeing results.

## Corpus

- **NEW holdout corpus**: 200+ projects, blind-authored (author never sees
  Aegis rules). MUST NOT reuse any of the round-2 205 projects.
- **Must include Pulumi YAML projects** (both `template:`-nested and
  top-level layouts) — this round specifically tests the Pulumi recovery.
- Formats: terraform, cloudformation, arm, bicep, pulumi, dockerfile,
  compose, kubernetes. Target ≥15 Pulumi projects.
- Profiles: vulnerable / secure / mixed, easy / medium / hard.
- Manifest with per-project: id, format, cloud, difficulty, profile,
  description.

## Ground truth

- Two independent labelers → adjudicated firm concepts (critical/high).
- Labelers see the code, NOT scanner output.
- Inter-labeler agreement reported (Cohen's κ or % agreement).

## Scanners (pinned)

- Aegis: frozen binary from candidate commit (`go build ./cmd/aegis`)
- Checkov 3.3.26, KICS 2.1.20, Trivy (pinned version, recorded)
- Equivalent configs: same severity scope, same exclusions, documented.

## Metrics

Per scanner: precision, recall, F1, FP rate, FN rate, median scan time,
failures, peak memory.
- 95% CIs via cluster-bootstrap by project (10,000 resamples; project is
  the sampling unit).
- FP adjudication: full adjudication of unmatched findings for the
  decision-relevant pairs; stratified samples (≥400) with two-level
  bootstrap for others.
- Pairwise differences with CIs; bold = CI excludes 0.

## Pulumi-specific acceptance

- Vulnerable Pulumi fixtures → expected rules fire.
- Secure Pulumi fixtures → no critical/high findings.
- Both layouts (`template:` and top-level) covered.
- Diagnostics disclose layout used.

## Exclusions & limitations

- Pulumi TS/Python/Go/.NET: out of scope (all scanners).
- Partial `${var}-suffix` interpolation: known Aegis limitation.
- Recorded in the final report.

## Deliverables

- `docs/audit/raw/final-eval-r3/`: corpus, manifest, ground truth,
  scanner outputs, adjudications, scripts, timing.
- `docs/audit/12_FINAL_EVAL_R3_REPORT.md`: metrics, CIs, per-criterion
  verdicts, limitations, reproducible commands.
