# Round-4 Evaluation Protocol (PRE-REGISTERED)

**Date:** 2026-10-13
**Status:** FROZEN before execution. Written before any R4 corpus generation,
labeling, scanning, or scoring. No changes after results are seen.
**Candidate:** branch `mission/top-tier-validation`, HEAD `2fbe955`
("Fix module duplicate findings (bare twins)"), lineage includes
`mission/accuracy-100` (`b495abd`) — 1,151 rules.
**Supersedes:** nothing. Rounds 2, 3, and the R3 rescore stand as separate
evidence with their own corpora/scorers; §9 reconciles them.

## Why R4 exists

The R3 rescore (`docs/audit/13_ACCURACY_100_REPORT.md`) reached F1 1.000,
precision 1.000, recall 1.000, FP rate 0.000 — on the SAME 210-project
corpus whose failures motivated the fixes, with the same labels and the same
scorer. That is a regression check, not independent evidence: the fixes were
tuned against exactly the failures they then "passed". R4 is the fresh
blind test that decides whether the accuracy-100 fixes generalize to unseen
code, or only memorized R3's corpus. R4's verdict — not the rescore — is the
evidence that may or may not support any superiority claim.

## 1. Win condition (UNCHANGED from rounds 2 and 3)

Aegis wins iff ALL THREE hold vs Checkov 3.3.26, KICS 2.1.20, and Trivy 0.74.0:
- (a) **Highest F1** (firm concepts, adjudicated)
- (b) **Lowest FP rate** (adjudicated)
- (c) **Fastest** median per-project scan time (2× decision threshold)

All three required. No partial credit. No threshold changes after results.

Decision rules (fixed):
- (a) PASS iff every pairwise (Aegis − competitor) F1 95% CI lies entirely
  above 0.
- (b) PASS iff every pairwise (competitor − Aegis) FP-rate 95% CI lies
  entirely above 0 (i.e. Aegis decisively lowest). A CI containing 0 is
  FAIL (not a tie) for the win condition, though the report will say
  whether the gap is a genuine tie (half-width < 2pp) or inconclusive.
- (c) PASS iff Aegis median-of-medians is > 2× faster than every competitor.

## 2. Corpus construction

- **Size:** ≥ 200 NEW projects, IDs `r4001`–`r42xx`, under
  `docs/audit/raw/final-eval-r4/corpus/` with `MANIFEST.json`
  (id, format, cloud, difficulty, profile, description).
- **Freshness (hard requirement):** zero exact-duplicate files (SHA-256)
  vs the round-2 corpus (`docs/audit/raw/final-eval/corpus/`) and the
  round-3 corpus (`docs/audit/raw/final-eval-r3/corpus/`), and zero
  exact-duplicate files within R4. Verified by hash before labeling; any
  collision is regenerated, not hand-edited to match a scanner.
- **Anti-memorization:** the generator MUST include new block shapes and
  new concept classes not present in R3 (different syntax shapes, new
  resource types, novel block combinations), so that passing R4 requires
  generalization, not recall of R3 fixtures. At least 12 new concept
  classes and at least one new file-shape variant per format family.
  The generator seed is fixed before generation (20261014) and recorded.
- **Formats (target counts, total ≥ 200):** terraform 40, cloudformation 30
  (YAML + JSON), arm 15, bicep 15, pulumi 20 (10 `template:`-nested + 10
  top-level), dockerfile 30, compose 25, kubernetes 35. (Same shape as R3
  for comparability; exact counts recorded in the manifest.)
- **Profiles:** ~40% vulnerable / ~30% secure / ~30% mixed (targets;
  actuals recorded). Difficulty ~40% easy / ~40% medium / ~20% hard.
- **Labeling-blind authoring:** block patterns come from generic,
  industry-standard IaC security concepts. The generator author does not
  consult Aegis rule sources during authoring. (Residual risk: the same
  agent authored R3 blocks and knows the R3 failure classes. Mitigation:
  new classes/shapes above + fresh labeling from code + §9 disclosure.
  This risk is stated, not hidden.)
- **Injection plan sealed:** the generator writes its intended concepts to
  `sealed/injection-plan.json`. It is NOT ground truth and is NOT consulted
  during labeling. It is used only afterwards for a QA completeness check
  (every injected firm concept must appear in GT or have a written reason
  why it is not a firm concept).

## 3. Labeling procedure

- **Two sequential labeling passes (A, then B)** over the generated code.
  Both passes read code only — NEVER scanner output, NEVER the injection
  plan, NEVER the other pass's file. Each records concepts as
  (project, resource, condition, severity-estimate).
- **Labeler-independence limitation (disclosed upfront):** this evaluation
  runs in an environment where the executing agent cannot spawn
  independent labeling subagents. Both passes are therefore performed by
  the same agent, sequentially, with the second pass performed without
  opening the first pass's file — the same limitation round 3 disclosed
  (§7.1 of the R3 report). Pass B additionally uses an independent
  pattern-scan of file contents (different detection patterns from the
  generator) as a cross-check. This is procedural independence, NOT
  personal independence, and it weakens the blind-labeling claim relative
  to round 2 (8 labelers). The report will state this in Limitations and
  will NOT claim "independent labelers" without the qualifier.
- **Adjudication:** disagreements go to a third pass applying the fixed
  criteria below. Firm concepts = adjudicated GENUINE with agreement or
  resolved disagreement. Soft/uncertain concepts tracked separately,
  not scored.
- **Adjudication criteria (fixed, same as rounds 2–3):**
  - GENUINE = factually correct finding of a real, actionable security
    weakness or missing security control (including availability and
    detection controls).
  - FP = factually wrong finding, by-design configuration flagged without
    context, or non-security pedantry.
  - HYGIENE-EXCLUDED = finding types reclassified per §4 (excluded from FP
    scoring for all scanners equally).
- **Agreement recorded:** raw agreement rate + Jaccard at (project, class)
  level, and Cohen's κ where computable. Pre-adjudication agreement is
  reported, not just post-adjudication 100%.
- **Scope:** firm concepts are critical/high only (same as R3). Medium/low
  concepts recorded separately as soft concepts, not scored.

## 4. Hygiene reclassification (labeling decision, NOT a detection change)

No Aegis code or rules are modified for this evaluation. The same 9
round-2 hygiene rule IDs are excluded from FP accounting for ALL scanners
equally (unchanged set — no additions after seeing R4 results):

`AEGIS-AWS-706`, `AEGIS-AZURE-111`, `AEGIS-GCP-215`, `AEGIS-TF-004`,
`AEGIS-AWS-658`, `AEGIS-AWS-684`, `AEGIS-AWS-798`, `AEGIS-GCP-114`,
`AEGIS-AWS-699`.

Rationale recorded in `docs/audit/raw/final-eval/hygiene-review.md`.
The canonical exposure class (`AEGIS-AWS-004`, 0.0.0.0/0 ingress) stays
SCORED. FP adjudication may additionally mark individual findings HYGIENE
(non-security pedantry) under the fixed §3 criteria; those verdicts are
recorded per finding with justification, never as blanket rule exclusions
added after results.

## 5. Scanners, versions, configurations (pinned)

| Scanner | Version | Binary | Config |
|---|---|---|---|
| Aegis | 1,151 rules @ `2fbe955` | `/tmp/aegis-item1/aegis` (built from HEAD; SHA-256 recorded in report) | `aegis scan <dir> --format=json`, default packs |
| Checkov | 3.3.26 | `~/workspace/.venv-checkov/bin/checkov` | `-d <dir> -o json --quiet`, default frameworks |
| KICS | 2.1.20 | `~/workspace/bin/kics` | `scan -p <dir> --queries-path ./assets/queries` |
| Trivy | 0.74.0 | `~/workspace/bin/trivy` | `config --skip-version-check --skip-check-update --format json`, misconfig-only |

- Equivalent severity scope and exclusions across scanners; per-run
  commands recorded in each scanner's `RUNLOG.md`.
- **Accuracy:** 1 run per project per scanner (KICS: batched scans with
  per-project attribution via file paths, as in R3 — per-project KICS runs
  are prohibitively slow; the batching is a runtime optimization, not a
  config change).
- **Timing:** 5 timed runs per scanner per project on a fixed 30-project
  stratified subset (5 per format group + Pulumi both layouts), recorded
  in `TIMING.json`. KICS timing: single run per subset project (documented
  deviation, same as rounds 2–3; cannot flip criterion (c) given the
  > 100× gaps observed).
- A failed or incomplete scan is NEVER counted as zero findings. Exit
  codes, timeouts, OOMs recorded in `FAILURES.json` / run logs.

## 6. Metrics

Per scanner, per format, per provider, and overall:
- **Precision** = TP / (TP + FP), **Recall** = TP / (TP + FN),
  **F1** = 2PR/(P+R), **FP rate** = FP / (TP + FP),
  **FN rate** = FN / (TP + FN).
- TP/FP/FN counted at the (project, concept-class) level against
  adjudicated firm concepts: for each (project, class),
  TP = min(firm concepts, matched findings). A scanner finding matches a
  concept if it identifies the same resource and condition (classifier
  mapping recorded in `score.py`; classifier changes, if any, must be made
  BEFORE scanner results are seen, or documented in a changelog with
  justification and must not add classes or move thresholds).
- TP/FP for unmatched findings come from FP adjudication (§7): adjudicated
  genuine findings (labeler-missed real issues) count as TP in the
  precision/FP-rate computation, exactly as in rounds 2–3. FN is counted
  against firm concepts only.

### Format-scope rule (pre-registered)

When a scanner does not natively support a format, that is a **coverage
gap, disclosed — not silently penalized and not silently excused**:
- The **primary** metrics (used for the win condition) are computed over
  ALL firm concepts, as in rounds 2–3, so R4 is comparable to prior rounds.
- A **secondary coverage-adjusted view** is reported alongside: per-scanner
  metrics restricted to the formats that scanner natively supports, plus a
  per-format × per-scanner coverage matrix showing which scanners even
  attempt each format and their per-format F1/FP rate on supported formats.
- The report will state plainly which formats each scanner skips (e.g.
  Checkov: no Pulumi/compose misconfiguration checks; Trivy: no
  Pulumi/compose/Bicep) and will NOT present a scanner's overall recall as
  a pure quality measure without noting its coverage scope.

## 7. FP adjudication

- **Full adjudication** of every unmatched finding for Aegis and Checkov.
- **Stratified samples (≥ 400)** for KICS and Trivy, with two-level
  bootstrap (binomial redraw) for their FP fractions.
- Fixed verdicts: TP / FP / HYGIENE per the §3 criteria, with a written
  justification per rule class (and per finding for context-sensitive
  rules). Adjudication is against the actual code, never against scanner
  reputation or prior-round verdicts: a rule that was FP in R3 is FP in R4
  only if the R4 instances are FP on their own code facts.
- **Re-adjudication guard:** if an adjudication pass is later found to have
  applied the wrong criterion (as happened in round 2 with probes/
  healthchecks), the correction is documented as a numbered pass with
  before/after counts — never silently overwritten.

## 8. Statistical method

- **Sampling unit = project.** Findings within a project are correlated;
  resampling findings would understate uncertainty.
- **95% CIs:** cluster bootstrap by project, B = 10,000 resamples
  (resample projects with replacement, recompute metrics, take
  2.5th/97.5th percentiles). Seed fixed (20261014) and recorded.
- **Pairwise differences:** bootstrap the difference (Aegis − competitor)
  for F1 and FP rate; bold = CI excludes 0.
- **Speed:** median of per-project medians across 5 runs (KICS: single
  runs); declared faster iff median ratio > 2×.
- All analysis code lives under `docs/audit/raw/final-eval-r4/` and is
  preserved with the results.

## 9. Reconciliation (pre-registered analysis, not a verdict change)

The final report MUST contain a reconciliation section explaining, in one
place, why the headline numbers differ across rounds:
- Round 2: Aegis F1 0.367 — (project, class) min-counting matcher, full FP
  adjudication exposing the FP tail, fresh dense 205-project corpus.
- Round 3: Aegis F1 0.733 — critical/high-only firm concepts (narrower GT
  universe), rule-level FP adjudication, different corpus.
- R3 rescore: F1 1.000 — SAME corpus/labels/scorer as R3 after fixes
  tuned against R3's failures. Tuning risk; must never be presented as
  independent evidence.
- R4: fresh corpus, fresh labels, same win condition. R4 is the only round
  that tests whether the accuracy-100 fixes generalize.
The reconciliation will name the three distinct causes — different corpora,
different scorers/GT scope, tuning — and will not present any round's
number as directly comparable to another's without those caveats.

## 10. Artifacts to preserve

`docs/audit/raw/final-eval-r4/`: `gen_corpus_r4.py`, `corpus/`,
`MANIFEST.json`, `sealed/injection-plan.json`, labeling passes +
adjudication log + inter-rater stats, `ground-truth.json`,
`scanner-output/<scanner>/` (raw outputs + `RUNLOG.md` + `TIMING.json` +
`FAILURES.json`), `labels/` (FP candidates + adjudications),
`score.py`, `fp_sample.py`, `stats.py`, `scores/`, `RUNLOG.md`.
Frozen Aegis binary: `/tmp/aegis-item1/aegis` (SHA-256 recorded; binary
path per task assignment — rebuild command recorded for reproducibility).

## 11. Reporting

`docs/audit/14_FINAL_EVAL_R4_REPORT.md`: frozen commit SHA + binary SHA-256,

---

## Addendum B — 2026-10-13: labeling-standard calibration (before labeling/scanning)

The labeling standard was calibrated against round 3's ACTUAL ground truth
(injected concepts vs `ground-truth.json` in the R3 raw dir), not against
R3's generator alone. Findings:
- R3 labelers kept every injected class as firm EXCEPT: `docker-latest`,
  `docker-no-healthcheck`, `k8s-no-limits`, `k8s-no-probe`,
  `k8s-no-networkpolicy`, `gcp-bucket-no-cmek` (judged medium/low, not firm).
- R3 labelers used `secret-hardcoded` (not `docker-secret`) for ALL hardcoded
  secrets, including Compose service-environment secrets.
- R3 labelers applied a salient-weakness rule: incidental absences on
  otherwise-bare fixtures were NOT labeled (e.g. a `hostPath` fixture did
  not also get `k8s-no-security-context`); absence classes were labeled
  only where the resource was otherwise hardened on the other axes.

R4 adopts the same standard, with two disclosed, pre-registered deviations
(applied uniformly, before any scanner output is seen):
1. Dockerfile ENV/ARG secrets ARE labeled firm `secret-hardcoded` (R3
   labeled Compose-env but not Dockerfile-env secrets). Same weakness,
   same verdict — the R3 asymmetry is not replicated.
2. New R4 classes are judged by R3's bar: explicit-disable / presence-based
   high-severity weaknesses are firm (`alb-public`, `es-no-encryption`,
   `elasticache-no-encryption`, `sqs-no-encryption`, `aks-no-rbac`,
   `cosmosdb-public`, `cloudtrail-no-validation`, `compose-host-network`,
   `git-exposed`, `sudo-nopasswd`); absence/medium classes are soft, not
   firm (`no-flowlog`, `no-audit-log`, `no-waf`, `k8s-nodeport`,
   `k8s-default-sa`, `compose-no-limits`), exactly as R3 treated
   `k8s-no-limits` / `k8s-no-probe` / `k8s-no-networkpolicy`.

every metric with 95% CIs, per-criterion (a)/(b)/(c) PASS/FAIL under the
§1 decision rules, per-format and per-provider tables, coverage matrix,
regressions vs prior rounds, limitations (including the §3
labeler-independence limitation), the §9 reconciliation, and verdict
EARNED / NOT YET / INCONCLUSIVE. If inconclusive, stated plainly with the
statistical reason. No universal-superiority claim unless the evidence
supports the exact claim worded.
