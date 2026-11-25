# Round-6 Evaluation Protocol (PRE-REGISTERED)

**Date:** 2026-11-25
**Status:** FROZEN before labeling, scanning, or scoring. Written before any R6
labeling pass, scanner run, or score computation. No changes after results
are seen; any correction needed later is a numbered addendum with
before/after, never a silent edit.
**Candidate:** Aegis **v2.3.0**, 1,140 rules, built from git tag `v2.3.0`
(commit `0dc955c7` — "Release v2.3.0 — the five-agent test release").
Binary: `~/workspace/aegis-engine-v230/aegis`, SHA-256
`4ad966af8c79a3293c0ff7563fc23d3f1e741aebc5c696950c1cc3ea592bb277`
(verified 2026-11-25: `aegis --version` reports
`aegis 2.3.0 (build 2026-11-24T20:40:50Z, commit 0dc955c7ec49b0b0023a5eda8af26b8fd033b7d6)`).
**Supersedes:** nothing. Rounds 2, 3, 4, and 5 stand as separate evidence with
their own corpora/scorers; §9 reconciles them.

## Why R6 exists

Round 5 (`docs/audit/raw/final-eval-r5/`, run 20–21 Oct 2026, Aegis 2.0.0-era
binaries, no protocol doc, no final report) measured Aegis recall 0.547 /
Checkov recall 0.273 on a 210-project blind corpus (n_firm 128), but its
carried adjudication standard scored "real but immaterial / by-design"
findings as FP, producing a misleading point precision of 0.090 for Aegis.
Re-verification (`PRECISION-RECONCILIATION.md`, 2026-10-20) showed true
factual FP was ~6–19 of 721 carried FPs and factual precision ~0.79–0.92:
R5's problem statement was recall and coverage, not correctness of what
fires — but the headline number said the opposite. R6 is the fresh blind
test of **Aegis v2.3.0** that (a) re-tests generalization on unseen code
with a brand-new corpus, and (b) pre-registers the **factual FP standard**
(§3, §7) so the precision number cannot be distorted the same way again.
R6's verdict — not R5's carried numbers — is the evidence that may or may
not support any superiority claim for v2.3.0.

**Scope note:** R6 is Aegis vs Checkov ONLY. KICS and Trivy are out of scope
for this round (no KICS/Trivy runs, no KICS/Trivy scoring). The win
condition in §1 is pairwise Aegis vs Checkov.

## 1. Win condition

Aegis wins iff ALL THREE hold vs Checkov 3.3.26:
- (a) **Highest F1** (firm concepts, adjudicated)
- (b) **Lowest FP rate** (adjudicated, factual standard §7)
- (c) **Fastest** median per-project scan time (2× decision threshold)

All three required. No partial credit. No threshold changes after results.

Decision rules (fixed):
- (a) PASS iff the pairwise (Aegis − Checkov) F1 95% CI lies entirely
  above 0.
- (b) PASS iff the pairwise (Checkov − Aegis) FP-rate 95% CI lies entirely
  above 0 (i.e. Aegis decisively lowest). A CI containing 0 is FAIL (not a
  tie) for the win condition, though the report will say whether the gap is
  a genuine tie (half-width < 2pp) or inconclusive.
- (c) PASS iff Aegis median-of-medians is > 2× faster than Checkov.

## 2. Corpus construction

- **Size:** 210 NEW projects, IDs `r6001`–`r6210`, under
  `docs/audit/raw/final-eval-r6/corpus/` with `MANIFEST.json`
  (id, format, cloud, difficulty, profile, description) and `STATS.json`.
  Generator: `docs/audit/raw/final-eval-r6/gen_corpus_r6.py`, seed **20261125**
  (fixed before generation, recorded in the generator, the manifest, and
  this protocol).
- **Freshness (hard requirement):** zero exact-duplicate files (SHA-256)
  vs the round-2 corpus (`docs/audit/raw/final-eval/corpus/`), the round-3
  corpus (`docs/audit/raw/final-eval-r3/corpus/`), the round-4 corpus
  (`docs/audit/raw/final-eval-r4/corpus/`), and the round-5 corpus
  (`docs/audit/raw/final-eval-r5/corpus/`), and zero exact-duplicate files
  within R6. Verified by hash BEFORE labeling; any collision is regenerated,
  not hand-edited to match a scanner. Method: every generated file carries
  a per-project header that is format-safe and semantics-preserving — a
  `# R6 project <pid>` comment line for Terraform, Bicep, YAML, and
  Dockerfiles, and a metadata section for JSON templates (ARM
  `"metadata": {"r6-project": pid}`, CloudFormation JSON
  `"Metadata": {"R6Project": pid}`). Pre-labeling verification (2026-11-25):
  **226 files, 0 within-R6 duplicate hashes, 0 cross-round duplicate
  hashes** (vs all four prior corpora). All 226 files parse (YAML with
  duplicate-top-level-key detection, JSON); zero duplicate Terraform
  resource declarations within any merged file.
- **Anti-memorization:** 25 new concept classes never present in R3/R4/R5
  (verified against the union of R3/R4/R5 generator concept lists and the
  R3/R4/R5 ground-truth class lists — 17 firm, 8 soft; see §3 Addendum C),
  plus at least one new file-shape variant per format family: two-file
  Terraform projects (`main.tf` + `variables.tf`); CloudFormation
  Parameters + Mappings sections; ARM `variables` + `outputs` sections;
  Bicep `@description`/`@allowed` decorators + `output` declarations;
  two-file Pulumi projects (`Pulumi.yaml` + `Pulumi.dev.yaml` stack
  config); multi-stage Dockerfiles leaking a secret file into the final
  stage; Compose `x-common` anchors + `configs:` + long-syntax
  `depends_on`; DaemonSet and Job kinds in Kubernetes. 70 projects use at
  least one new R6 block; all 25 new classes are injected at least once
  (forced-coverage queue in the generator guarantees each new class
  appears; 5 new blocks whose classes are covered by other-format
  variants were never picked — disclosed in `HANDOFF.md`, not hidden).
- **Formats (exact counts):** terraform 40, cloudformation 30, arm 15,
  bicep 15, pulumi 20 (10 `template:`-nested + 10 top-level), dockerfile 30,
  compose 25, kubernetes 35. Total 210.
- **Profiles (actuals):** vulnerable 84 (40%), secure 65 (31%),
  mixed 61 (29%). Difficulty: easy 92 (44%), medium 80 (38%), hard 38 (18%).
  Clouds: aws 60, azure 35, gcp 1, multi 24, none 90.
- **Labeling-blind authoring:** block patterns come from generic,
  industry-standard IaC security concepts. The generator author does not
  consult Aegis rule sources during authoring. (Residual risk: the same
  agent authored R3/R4/R5 blocks and knows the prior failure classes.
  Mitigation: new classes/shapes above + fresh labeling from code + §9
  disclosure. This risk is stated, not hidden.)
- **Injection plan sealed:** the generator writes its intended concepts to
  `sealed/injection-plan.json`. It is NOT ground truth and is NOT consulted
  during labeling. It is used only afterwards for a QA completeness check
  (every injected firm concept must appear in GT or have a written reason
  why it is not a firm concept).
- **FN ground truth sealed:** the generator also writes
  `sealed/fn-manifest.json` — per project, the expected findings
  (concept class, primary resource locator, condition). It is NOT consulted
  during labeling. After labeling it is used for (1) the QA completeness
  check and (2) FN scoring: **recall is scored against this ground truth,
  not against Aegis's own labels and not against the labelers' concepts
  alone**. The `resource` string in each entry is a locator hint (the first
  declared resource of the injected block); scoring matches on
  (project, concept-class) per §6, not on that string. Both sealed files
  carry a README stating they were sealed before labeling and must not be
  opened until labeling is complete.

## 3. Labeling procedure

- **Two sequential labeling passes (A, then B)** over the generated code.
  Both passes read code only — NEVER scanner output, NEVER the injection
  plan, NEVER the FN manifest, NEVER the other pass's file. Each records
  concepts as (project, resource, condition, severity-estimate).
- **Labeler-independence limitation (disclosed upfront):** this evaluation
  runs in an environment where the executing agent cannot spawn
  independent labeling subagents. Both passes are therefore performed by
  the same agent, sequentially, with the second pass performed without
  opening the first pass's file — the same limitation rounds 3–5 disclosed.
  Pass B additionally uses an independent pattern-scan of file contents
  (different detection patterns from the generator) as a cross-check. This
  is procedural independence, NOT personal independence, and it weakens
  the blind-labeling claim relative to round 2 (8 labelers). The report
  will state this in Limitations and will NOT claim "independent labelers"
  without the qualifier.
- **Adjudication:** disagreements go to a third pass applying the fixed
  criteria below. Firm concepts = adjudicated GENUINE with agreement or
  resolved disagreement. Soft/uncertain concepts tracked separately,
  not scored.
- **Adjudication criteria (fixed, same as rounds 2–4, PLUS the factual-FP
  standard for §7):**
  - GENUINE = factually correct finding of a real, actionable security
    weakness or missing security control (including availability and
    detection controls).
  - FP (labeling sense) = factually wrong finding, by-design configuration
    flagged without context, or non-security pedantry. (For the §7 FP
    adjudication of unmatched scanner findings, the factual standard below
    supersedes the "by-design / pedantry" clause: see §7.)
  - HYGIENE-EXCLUDED = finding types reclassified per §4 (excluded from FP
    scoring for all scanners equally).
- **FACTUAL FP STANDARD (predeclared — the R5 lesson):** an unmatched
  scanner finding is FP **only if the flagged condition is factually
  absent or misread in the code**. A finding whose flagged condition
  factually holds — even if the labeler judges it immaterial, by-design,
  or not part of ground truth — is **LABEL-NOISE**, not FP. LABEL-NOISE is
  tracked separately, reported with its count, and **never counted as FP**
  in any precision or FP-rate computation. The primary precision is
  TP / (TP + FP_factual); a secondary "factual precision"
  (TP + LABEL-NOISE) / (TP + FP_factual + LABEL-NOISE) is reported
  alongside. The R5 carried standard (immaterial/by-design ⇒ FP) is
  explicitly NOT used in R6.
- **Agreement recorded:** raw agreement rate + Jaccard at (project, class)
  level, and Cohen's κ where computable. Pre-adjudication agreement is
  reported, not just post-adjudication 100%.
- **Scope:** firm concepts are critical/high only (same as R3–R5).
  Medium/low concepts recorded separately as soft concepts, not scored.

### Addendum C — R6 labeling-standard calibration (before labeling)

Calibrated against R4 Addendum B and R5's adjudicated ground truth:
- R5's adjudicated firm classes carry over as firm unless noted:
  `secret-hardcoded`, `db-public`, `redis-non-ssl`, `ecr-public-policy`,
  `k8s-run-as-root`, `sg-admin-public`, `apigw-no-auth`, `nsg-rdp-public`,
  `compose-db-port-published`, `k8s-cluster-admin-binding`,
  `ebs-snapshot-public`, `cloudsql-ssl-disabled`, `storage-unencrypted`,
  `compose-cap-add-sys-ptrace`, `k8s-host-namespace`, `k8s-cap-sys-admin`,
  `kafka-plaintext`, `docker-curl-pipe-shell`, `k8s-privileged`,
  `cloudfront-origin-http-only`, `compose-host-network`,
  `compose-privileged`, `compose-docker-sock`.
- R5's adjudicated SOFT classes stay soft: `docker-eol-base`,
  `k8s-hostpath-mount` (readOnly hostPath), `vm-encryption-at-host-disabled`,
  `weak-password-policy`, `acr-admin-user-enabled`, `dnssec-off`,
  `docker-healthcheck-disabled`, `docker-sshd`, `https-not-enforced`
  (`httpsOnly=false` on Web/Function Apps), `iam-weak-password-policy`.
  (R5's `https-not-enforced` soft verdict governs the R6 class
  `az-webapp-no-https` below.)
- R4's firm `weak-tls` governs the R6 class `alb-tls-old` (explicit
  deprecated-TLS policy) and `az-sql-weak-tls`.
- The salient-weakness rule stands: incidental absences on otherwise-bare
  fixtures are NOT labeled (e.g. a `hostPath` fixture does not also get
  `k8s-no-security-context`); absence classes are labeled only where the
  resource is otherwise hardened on the other axes. Dockerfile ENV/ARG
  secrets ARE labeled firm `secret-hardcoded` (R4 deviation from R3,
  retained).
- New R6 classes, judged by the same bar (predeclared before labeling):

  | class | firm/soft | rationale |
  |---|---|---|
  | `ecs-public-ip` | **firm** | presence-based public exposure of tasks |
  | `alb-tls-old` | **firm** | explicit TLS 1.0 policy (R4 `weak-tls`) |
  | `elasticache-no-auth` | **firm** | plaintext cache channel, no auth token |
  | `opensearch-no-https` | **firm** | explicit `enforce_https=false` |
  | `sqs-public-policy` | **firm** | queue policy grants `Principal "*"` |
  | `sns-public-policy` | **firm** | topic policy grants `Principal "*"` |
  | `lambda-invoke-public` | **firm** | invoke allowed from `Principal "*"` |
  | `neptune-no-encryption` | **firm** | explicit `storage_encrypted=false` |
  | `efs-unencrypted` | **firm** | explicit `encrypted=false` |
  | `bigquery-public` | **firm** | dataset grants `dataViewer` to `allUsers` |
  | `az-mysql-public` | **firm** | public network access on a database |
  | `az-vm-password-auth` | **firm** | explicit password-auth enablement |
  | `az-storage-http-only` | **firm** | explicit plain-HTTP traffic allowed |
  | `docker-multistage-secret` | **firm** | secret file shipped in the final image |
  | `compose-host-pid` | **firm** | host PID namespace sharing (R4 host-namespace precedent) |
  | `k8s-seccomp-unconfined` | **firm** | explicit `Unconfined` on an otherwise-hardened workload |
  | `k8s-hostpath-writable` | **firm** | writable host mount (container-escape primitive; strictly stronger than R5's soft readOnly hostPath) |
  | `gke-no-network-policy` | soft | absence of network-policy enforcement (R4 `k8s-no-networkpolicy` precedent) |
  | `az-webapp-no-https` | soft | R5 `https-not-enforced` precedent |
  | `cognito-weak-password` | soft | weak-password-policy precedent (R5) |
  | `secrets-no-rotation` | soft | absence-based (no rotation configured) |
  | `ecr-tag-mutable` | soft | medium tampering risk, no direct exposure |
  | `docker-expose-sensitive-port` | soft | `EXPOSE` documents a port; it does not publish it |
  | `compose-run-as-root` | soft | absence-based (no `user:` set) |
  | `k8s-lb-service` | soft | LoadBalancer exposure without restriction (R4 `k8s-nodeport` precedent) |

## 4. Hygiene reclassification (labeling decision, NOT a detection change)

No Aegis code or rules are modified for this evaluation. The same 9
round-2 hygiene rule IDs are excluded from FP accounting for ALL scanners
equally (unchanged set — no additions after seeing R6 results):

`AEGIS-AWS-706`, `AEGIS-AZURE-111`, `AEGIS-GCP-215`, `AEGIS-TF-004`,
`AEGIS-AWS-658`, `AEGIS-AWS-684`, `AEGIS-AWS-798`, `AEGIS-GCP-114`,
`AEGIS-AWS-699`.

Rationale recorded in `docs/audit/raw/final-eval/hygiene-review.md`.
The canonical exposure class (`AEGIS-AWS-004`, 0.0.0.0/0 ingress) stays
SCORED. FP adjudication may additionally mark individual findings HYGIENE
(non-security pedantry, e.g. style/lint findings whose subject is not a
security property) under the fixed §3/§7 criteria; those verdicts are
recorded per finding with justification, never as blanket rule exclusions
added after results.

## 5. Scanners, versions, configurations (pinned)

| Scanner | Version | Binary | Config |
|---|---|---|---|
| Aegis | v2.3.0, 1,140 rules @ `0dc955c7` | `~/workspace/aegis-engine-v230/aegis` (SHA-256 in header) | `aegis scan <dir> --format=json`, default packs |
| Checkov | 3.3.26 | `~/workspace/.venv-checkov/bin/checkov` (verified working 2026-11-25, Python 3.12.3) | `-d <dir> -o json --quiet`, default frameworks |

- Equivalent severity scope and exclusions across scanners; per-run
  commands recorded in each scanner's `RUNLOG.md`.
- **Accuracy:** 1 run per project per scanner.
- **Timing:** 5 timed runs per scanner per project on a fixed 30-project
  stratified subset (5 per format group + Pulumi both layouts), recorded
  in `TIMING.json`.
- A failed or incomplete scan is NEVER counted as zero findings. Exit
  codes, timeouts, OOMs recorded in `FAILURES.json` / run logs.

## 6. Metrics

Per scanner, per format, per provider, and overall:
- **Precision** = TP / (TP + FP), **Recall** = TP / (TP + FN),
  **F1** = 2PR/(P+R), **FP rate** = FP / (TP + FP),
  **FN rate** = FN / (TP + FN).
  FP here is the **factual** FP of §7; LABEL-NOISE is excluded from the
  primary precision/FP-rate denominators and reported separately.
- TP/FP/FN counted at the (project, concept-class) level against
  adjudicated firm concepts: for each (project, class),
  TP = min(firm concepts, matched findings). A scanner finding matches a
  concept if it identifies the same resource and condition (classifier
  mapping recorded in `score.py`; classifier changes, if any, must be made
  BEFORE scanner results are seen, or documented in a changelog with
  justification and must not add classes or move thresholds).
- TP/FP for unmatched findings come from FP adjudication (§7): adjudicated
  genuine findings (labeler-missed real issues) count as TP in the
  precision/FP-rate computation, exactly as in rounds 2–5. FN is counted
  against firm concepts only — and FN is scored against the sealed
  FN ground truth (`sealed/fn-manifest.json`, §2), not against the
  labelers' concepts alone: a firm concept in the FN manifest that no
  scanner matched is an FN even if labeling missed it; the QA
  completeness check (§2) reconciles any manifest/GT delta in writing.
  (In R5 the auto scorer used the adjudicated GT for FN; R6 pre-registers
  the FN manifest as the recall authority so that a labeling miss cannot
  hide a scanner miss.)

### Format-scope rule (pre-registered)

When a scanner does not natively support a format, that is a **coverage
gap, disclosed — not silently penalized and not silently excused**:
- The **primary** metrics (used for the win condition) are computed over
  ALL firm concepts, as in rounds 2–5, so R6 is comparable to prior rounds.
- A **secondary coverage-adjusted view** is reported alongside: per-scanner
  metrics restricted to the formats that scanner natively supports, plus a
  per-format × per-scanner coverage matrix showing which scanners even
  attempt each format and their per-format F1/FP rate on supported formats.
- The report will state plainly which formats each scanner skips (e.g.
  Checkov: no Pulumi/compose misconfiguration checks) and will NOT present
  a scanner's overall recall as a pure quality measure without noting its
  coverage scope.

## 7. FP adjudication

- **Full adjudication** of every unmatched finding for Aegis and Checkov
  (no sampling — two scanners only).
- Fixed verdicts under the **factual standard (§3)**: TP / FP / HYGIENE /
  **LABEL-NOISE**, with a written justification per rule class (and per
  finding for context-sensitive rules). Adjudication is against the actual
  code, never against scanner reputation or prior-round verdicts: a rule
  that was FP in R5 is FP in R6 only if the R6 instances are FP on their
  own code facts. A finding whose flagged condition factually holds is
  LABEL-NOISE even if an R5 adjudication called the same family FP under
  the old carried standard.
- **Re-adjudication guard:** if an adjudication pass is later found to have
  applied the wrong criterion (as happened in round 2 with probes/
  healthchecks, and in round 5 with the carried standard), the correction
  is documented as a numbered pass with before/after counts — never
  silently overwritten.

## 8. Statistical method

- **Sampling unit = project.** Findings within a project are correlated;
  resampling findings would understate uncertainty.
- **95% CIs:** cluster bootstrap by project, B = 10,000 resamples
  (resample projects with replacement, recompute metrics, take
  2.5th/97.5th percentiles). Seed fixed (**20261125**) and recorded.
- **Pairwise differences:** bootstrap the difference (Aegis − Checkov)
  for F1 and FP rate; bold = CI excludes 0.
- **Speed:** median of per-project medians across 5 runs; declared faster
  iff median ratio > 2×.
- All analysis code lives under `docs/audit/raw/final-eval-r6/` and is
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
- Round 4: Aegis P 1.000 / R 0.941 → 1.000 after Sprints 1–2 — fresh
  corpus, fresh labels, adjudicated ground truth, 136 concepts; the
  accuracy bedrock.
- Round 5: Aegis recall 0.547 (closeout 0.555), n_firm 128, no protocol
  doc, no final report — and its carried point precision 0.090 is a
  known artifact of the old adjudication standard; the re-verified
  factual precision is ~0.79–0.92. **The 0.090 figure must never be quoted
  without the factual correction.**
- R6: fresh corpus, fresh labels, factual FP standard, FN manifest as
  recall authority, Aegis v2.3.0 vs Checkov 3.3.26 only. R6 is the only
  round that tests v2.3.0's generalization under the corrected standard.
The reconciliation will name the distinct causes — different corpora,
different scorers/GT scope, different FP standards, tuning — and will not
present any round's number as directly comparable to another's without
those caveats.

## 10. Artifacts to preserve

`docs/audit/raw/final-eval-r6/`: `gen_corpus_r6.py`, `corpus/`,
`MANIFEST.json`, `STATS.json`, `sealed/injection-plan.json`,
`sealed/fn-manifest.json`, `sealed/README.txt`, labeling passes +
adjudication log + inter-rater stats, `ground-truth.json`,
`scanner-output/<scanner>/` (raw outputs + `RUNLOG.md` + `TIMING.json` +
`FAILURES.json`), `labels/` (FP candidates + adjudications),
`score.py`, `stats.py`, `scores/`, `RUNLOG.md`, `HANDOFF.md`.
Frozen Aegis binary: `~/workspace/aegis-engine-v230/aegis` (SHA-256 in
header; rebuild command recorded for reproducibility).

## 11. Reporting

`docs/audit/27_FINAL_EVAL_R6_REPORT.md`: frozen commit SHA + binary SHA-256,
every metric with 95% CIs, per-criterion (a)/(b)/(c) PASS/FAIL under the
§1 decision rules, per-format and per-provider tables, coverage matrix,
LABEL-NOISE accounting, FN-manifest reconciliation, regressions vs prior
rounds, limitations (including the §3 labeler-independence limitation),
the §9 reconciliation, and verdict EARNED / NOT YET / INCONCLUSIVE. If
inconclusive, stated plainly with the statistical reason. No
universal-superiority claim unless the evidence supports the exact claim
worded. The report number (27) is the next free number after
`26_AEGIS_FINAL_STATE.md`; if 27 is taken when the report is written, use
the next free number and note the change.

---

## Addendum 1 — 2026-11-25: ARM merge bug fix (before labeling completed)

**Before:** the generator's ARM merge carried only `resources` and
`parameters` from the second and later blocks into the merged template.
The new R6 block `arm_storage_httponly` declares its storage account name
as `[variables('accountName')]` with `variables` + `outputs` sections, so
in the three projects where it was merged second (r6079, r6080, r6084) the
`variables`/`outputs` sections were dropped and the template carried a
dangling `[variables('accountName')]` reference. Found during the Pass A
read-through (ARM files), before any ARM labels were written to files.

**Fix:** `merge_files` (ARM branch) now also merges `variables` and
`outputs` from later blocks (`setdefault` + `update`, same pattern as
`parameters`). Generator re-run with the same fixed seed 20261125.

**After / verification:** exactly 3 files changed (r6079, r6080, r6084
`azuredeploy.json`); the other 223 corpus files are byte-identical to the
pre-fix run (SHA-256 diff), so all Pass A notes recorded before the fix
(Terraform r6001–r6040, CloudFormation r6041–r6070) stand unchanged.
Overlap re-verified after the fix: 0 within-R6 duplicates, 0 cross-round
duplicates, 0 parse errors, 25/25 new classes still injected. No protocol
rule changed; this addendum records a generator bug fix only.
