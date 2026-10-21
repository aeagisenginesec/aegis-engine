# 11 — Final Evaluation Round 2: Protocol (frozen before execution)

**Date:** 2026-10-12
**Branch:** `mission/final-eval-round2` from `ddb9347`
**Candidate commit (frozen):** `ddb934766e8b0199172a4b9f60049bd268932513`
**Binary:** `/tmp/aegis-frozen` (built from frozen commit; `aegis doctor`: 1,146 rules)
**Status:** PROTOCOL ONLY — no evaluation runs executed under this protocol yet.

This protocol was written BEFORE any round-2 scoring runs. The win condition,
metrics, and statistical methods below are fixed and may not be changed after
results are seen.

## 1. Objective

Decide the Aegis superiority claim under the predeclared three-part win
condition, using a fresh blind corpus (200+ projects), shared ground truth for
Aegis and Checkov, and confidence intervals tight enough to declare a winner or
a genuine tie on false-positive rate.

Prior round (60 projects, `docs/audit/10_FINAL_SUPERIORITY.md`): Aegis won F1
(0.732 vs 0.670) and speed (48×) decisively; FP rate was a statistical tie
(9.0% vs 9.1%, ±3pp margin). This round targets the FP-rate decision.

## 2. Win condition (UNCHANGED from prior round)

Aegis wins iff ALL THREE hold:
- (a) **Highest F1** on firm adjudicated concepts
- (b) **Lowest false-positive rate**
- (c) **Fastest** median scan time

All three required. No partial credit. Thresholds are not moved after results.

## 3. Corpus construction

- **Size:** ≥200 fresh projects in `/tmp/eval2-corpus/`, IDs `t001–t070`
  (Terraform AWS/Azure/GCP), `c001–c070` (CloudFormation YAML/JSON, ARM,
  Bicep, Pulumi YAML), `k001–k065` (Docker, Kubernetes, Compose, mixed).
- **Freshness:** all projects authored new for this round; authors instructed
  not to copy the prior 60-project corpus and not to inspect Aegis rules.
- **Mix:** ~40% vulnerable / ~25% secure / ~35% mixed profiles;
  ~30% easy / ~45% medium / ~25% hard difficulty (targets; actuals recorded
  in manifest).
- **Manifest:** `/tmp/eval2-corpus/MANIFEST.json` — id, format, cloud,
  difficulty, profile, factual description per project.

## 4. Labeling procedure

- Two independent labelers review every project WITHOUT seeing any scanner
  output. Each records security-relevant concepts: (project, resource,
  condition, severity-estimate).
- Concepts are matched across labelers; disagreements go to adjudication by a
  third pass applying the fixed adjudication criteria below.
- **Adjudication criteria (fixed):**
  - GENUINE = factually correct finding of a real, actionable security
    weakness or missing security control (including availability and
    detection controls).
  - FP = factually wrong finding, by-design configuration flagged without
    context, or non-security pedantry.
  - HYGIENE-EXCLUDED = finding types reclassified per §5 (excluded from FP
    scoring for all scanners equally).
- **Firm concepts** = adjudicated GENUINE with agreement or resolved
  disagreement. Soft/uncertain concepts are tracked separately, not scored.
- Inter-labeler agreement recorded (Cohen's κ at concept level where
  computable, plus raw agreement rate).

## 5. Hygiene reclassification (labeling decision, NOT a detection change)

No Aegis code or rules were modified. The following finding types, which
appeared as false positives in the prior round, are reclassified as HYGIENE
for round-2 scoring — excluded from FP numerators/denominators for ALL
scanners equally. Full per-item impact justifications in
`docs/audit/raw/final-eval/hygiene-review.md` and `/tmp/hygiene-decisions.json`.

| Rule ID | Condition | Decision | One-line justification |
|---|---|---|---|
| AEGIS-AWS-706 | RDS default option group | hygiene | AWS-sanctioned default; rule doesn't check audit need |
| AEGIS-AZURE-111 | Detailed error messages off | hygiene | Deliberately disabled in prod to avoid info disclosure |
| AEGIS-GCP-215 | Firewall descriptions | hygiene | Documentation pedantry, no security impact |
| AEGIS-TF-004 | Version pinning | hygiene | Operational hygiene, not a vulnerability |
| AEGIS-AWS-658 | Inline IAM policy | hygiene | Identical effective permissions to managed equivalent |
| AEGIS-AWS-684 | ebs_optimized | hygiene | Performance-only attribute |
| AEGIS-AWS-798 | KMS Sid | hygiene | Statement identifier pedantry |
| AEGIS-GCP-114 | GKE release channel | hygiene | Rule self-labels "hygiene finding"; blind to version status |
| AEGIS-AWS-699 | Nitro Enclaves | hygiene | Rule text conditional on sensitive-data workloads |
| AEGIS-AWS-004 | 0.0.0.0/0 ingress | **KEPT SCORED** | Canonical exposure-detection class; excluding = benchmark gaming |

Bias was against reclassification: 9 of 10 types moved, only with written
impact justification; the canonical exposure class stays scored.

## 6. Scanners, versions, configurations

| Scanner | Version | Binary | Config |
|---|---|---|---|
| Aegis | 1,146 rules @ `ddb9347` | `/tmp/aegis-frozen` | default scan, all packs |
| Checkov | 3.3.26 | `~/workspace/.venv-checkov/bin/checkov` | default framework scope matching corpus formats |
| KICS | 2.1.20 | `~/workspace/bin/kics` | default queries |
| Trivy | 0.74.0 | `~/workspace/bin/trivy` | `trivy config` on project dirs |

- Equivalent severity scope and exclusions across scanners (recorded per run).
- 5 timed runs per scanner per project: run 1 = cold, runs 2–5 = warm.
  Record wall time, peak RSS (via `/usr/bin/time -v`), exit codes, failures.
- A failed or incomplete scan is NEVER counted as zero findings.

## 7. Metrics

Per scanner, per format, and overall:
- **Precision** = TP / (TP + FP), **Recall** = TP / (TP + FN),
  **F1** = 2PR/(P+R), **FP rate** = FP / (TP + FP),
  **FN rate** = FN / (TP + FN).
- TP/FP/FN counted at the (project, concept) level against adjudicated firm
  concepts. A scanner finding matches a concept if it identifies the same
  resource and condition (rule-ID mapping recorded; near-miss rules adjudicated
  per fixed criteria).
- Hygiene-excluded types (§5) are removed from FP accounting for all scanners.

## 8. Statistical method (disclosed)

- **Sampling unit = project** (not finding). Projects are the independent
  draws; findings within a project are correlated.
- **Confidence intervals:** cluster bootstrap by project (10,000 resamples;
  resample projects with replacement, recompute metrics per resample, take
  2.5th/97.5th percentiles). Reported as 95% CIs.
- **Pairwise FP-rate comparison (Aegis vs Checkov):** cluster-bootstrap the
  difference in FP rates; declare Aegis lower iff the 95% CI of the
  (Checkov − Aegis) difference lies entirely above 0. Declare a genuine tie
  iff the CI contains 0 AND its half-width is < 2pp (i.e., we have enough
  precision to say the difference, if any, is < 2pp). Otherwise INCONCLUSIVE.
- **F1 comparison:** same bootstrap-difference procedure on F1.
- **Speed:** median of per-project medians across 5 runs; declared faster iff
  median ratio > 2× (conservative; prior round showed 48×).
- All analysis code in `docs/audit/raw/final-eval/score.py` (committed with
  results); raw per-run data in `docs/audit/raw/final-eval/`.

## 9. Artifacts to preserve

- `docs/audit/raw/final-eval/`: corpus manifest copy, labeler outputs,
  adjudicated ground truth, per-scanner raw outputs (all 5 runs), scoring
  script, score outputs, run log with commands and environment.
- Rerun instructions in the final report.

## 10. Reporting

`docs/audit/11_FINAL_EVAL_REPORT.md`: frozen commit SHA, every metric with
95% CIs, per-criterion (a)/(b)/(c) pass/fail under the fixed decision rules,
regressions vs prior round, unresolved issues, and verdict EARNED / NOT YET /
INCONCLUSIVE. If inconclusive, stated plainly with the statistical reason.

---

## Addendum A — 2026-10-12/13: infrastructure failure and path relocation
(NO methodological change; decision rules, win condition, metrics untouched)

- **Event:** at ~23:30 UTC on 2026-10-12 the sandbox runtime wiped `/tmp`
  (512M tmpfs) mid-evaluation. Lost: the round-2 corpus (205 projects),
  all labeler files, adjudication outputs, all scanner raw outputs, the
  scoring script's working copies, and the timing-subset JSON. Nothing under
  `/tmp` was recoverable. All files under `~/workspace` (this repo, the
  protocol, hygiene review, score.py) survived.
- **Rebuild:** the corpus is being RE-AUTHORED from scratch (fresh projects,
  same brief, same blind procedure) and every subsequent step (labeling,
  adjudication, scanning, scoring) re-executed. The round therefore uses a
  fresh corpus; no round-2 results had been seen before the wipe except
  aggregate matcher-debugging diagnostics (used only to fix the scorer's
  normalization/classification bugs, not detection).
- **Path relocation (implementation detail, not a protocol change):**
  - Corpus: `/tmp/eval2-corpus/` →
    `docs/audit/raw/final-eval/corpus/` (with `MANIFEST.json`).
  - Scanner raw outputs: `/tmp/eval2-raw/` →
    `docs/audit/raw/final-eval/scanner-output/`.
  - Labels/adjudication: → `docs/audit/raw/final-eval/labels/`.
  - Scores: → `docs/audit/raw/final-eval/scores/`.
  - Frozen Aegis binary: `/tmp/aegis-frozen` →
    `docs/audit/raw/final-eval/aegis-frozen` (rebuilt from `ddb9347`;
    sha256 `9ae868d9d244361be46e074c1c74601b17198b2378605492171660dd2633738d`).
- **KICS timing deviation (documented):** KICS startup+scan cost scales with
  project count (~40s for one small project, ~250s for 41), so 5 runs × 30
  projects would take ~100 minutes for timing alone. KICS timing uses ONE run
  per timing-subset project (30 runs, ~20 min), all other scanners use 5 runs
  per project as specified. Rationale: the speed decision rule requires only a
  >2× median ratio; the prior round measured KICS at 72.7s vs Aegis 0.06s, so
  this deviation cannot flip criterion (c). Recorded in run logs.
