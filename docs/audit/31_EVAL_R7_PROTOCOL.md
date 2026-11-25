# Round-7 Evaluation Protocol (PRE-REGISTERED)

**Date:** 2026-11-25
**Status:** FROZEN before labeling, scanning, or scoring. Written before any R7
labeling pass, scanner run, or score computation. No changes after results
are seen; any correction needed later is a numbered addendum with
before/after, never a silent edit.
**Candidate:** Aegis **Phase B merged build**, 1,148 rules, built from branch
`phase-b/measure-combined` (commit `ca5e7f0` — "Phase B measurement: merge
Pulumi adapter fix + rules gap fixes"), based on master `814a99b`.
Binary: `/tmp/aegis-phaseb-r7`, SHA-256
`144a64dfd3cae0edae4ba4924492b49b3642e633121813590286d7706a5bd2c2`
(built 2026-11-25 with `CGO_ENABLED=0 go build`, Go 1.26.10, no ldflags —
`aegis --version` reports `aegis 2.3.0 (build unknown, commit unknown)`;
`aegis doctor` passed, 1,148 rules loaded, verified 2026-11-25).
If the binary is lost (e.g. a sandbox restart wipes /tmp), rebuild from the
same branch/commit with the same command and record the new SHA-256; the
rebuild must report 1,148 rules in `doctor` and the same `--version` string.
**Supersedes:** nothing. Rounds 2, 3, 4, 5, and 6 stand as separate evidence
with their own corpora/scorers; §9 reconciles them.

## Why R7 exists

Round 6 (`docs/audit/raw/final-eval-r6/`, 210-project blind corpus, seed
20261125, pre-registered frozen protocol, factual FP standard) gave the
verdict NOT YET for Aegis v2.3.0 vs Checkov 3.3.26: F1 lead +0.108 not
decisive (pairwise 95% CI [−0.024, +0.238]), FP rate Checkov 0.000 vs
Aegis 0.026. Phase B then closed the R6 coverage gaps on the frozen R6
corpus: F1 0.672 → 0.927, recall 0.513 → 0.863, TP 76 → 117, FN 57 → 16,
FP 2 → 0, speed 468× (`docs/audit/30_PHASE_B_MEASUREMENT.md`). But every
Phase B rule was built from R6 FN evidence — 8 new rules (AZURE-315,
AZURE-316, GCP-295, K8S-033, AWS-860, COMPOSE-010, DOCKER-038, SC-010),
the Pulumi adapter fix, and several rule retitles to match the scorer
classifier's keywords. Those are tuned-corpus numbers, not blind results;
the +0.255 F1 jump will shrink on fresh code. R7 is the fresh blind test
of the Phase B build that (a) re-tests generalization on unseen code with
a brand-new corpus, and (b) decides, under the same pre-registered win
condition and factual FP standard as R6, whether the Phase B gain is real
and whether Aegis now outperforms Checkov. R7's verdict — not the Phase B
tuned-corpus measurement — is the evidence that may or may not support any
superiority claim for the Phase B build.

**Disclosure (predeclared):** Phase B rules were tuned on R6 FNs,
including retitles to match classifier keywords. That tuning is disclosed
here and must be disclosed again in the R7 report. R7 measures the tuned
build on fresh code; it does not re-test the tuning.

**Scope note:** R7 is Aegis vs Checkov ONLY. KICS and Trivy are out of scope
for this round (no KICS/Trivy runs, no KICS/Trivy scoring). The win
condition in §1 is pairwise Aegis vs Checkov.

## 1. Win condition

Aegis wins iff ALL THREE hold vs Checkov 3.3.26:
- (a) **Highest F1** (firm concepts, adjudicated)
- (b) **Lowest FP rate** (adjudicated, factual standard §7)
- (c) **Fastest** median per-project scan time (2× decision threshold)

All three required. No partial credit. No threshold changes after results.

Decision rules (fixed, same as R6):
- (a) PASS iff the pairwise (Aegis − Checkov) F1 95% CI lies entirely
  above 0.
- (b) PASS iff the pairwise (Checkov − Aegis) FP-rate 95% CI lies entirely
  above 0 (i.e. Aegis decisively lowest). A CI containing 0 is FAIL (not a
  tie) for the win condition, though the report will say whether the gap is
  a genuine tie (half-width < 2pp) or inconclusive. A genuine 0–0 tie is a
  FAIL for (b) — the R4 precedent (Aegis failed (b) there on a genuine
  KICS tie). The criterion as written can only be won on a corpus where
  Checkov makes ≥1 FP and Aegis makes 0.
- (c) PASS iff Aegis median-of-medians is > 2× faster than Checkov.

## 2. Corpus construction

- **Size:** 210 NEW projects, IDs `r7001`–`r7210`, under
  `docs/audit/raw/final-eval-r7/corpus/` with `MANIFEST.json`
  (id, format, cloud, difficulty, profile, description) and `STATS.json`.
  Generator: `docs/audit/raw/final-eval-r7/gen_corpus_r7.py`, adapted from
  the R6 generator (`docs/audit/raw/final-eval-r6/gen_corpus_r6.py`),
  seed **20261126** (fixed before generation, recorded in the generator,
  the manifest, and this protocol).
- **Freshness (hard requirement):** zero exact-duplicate files (SHA-256)
  vs the round-2 corpus (`docs/audit/raw/final-eval/corpus/`), the round-3
  corpus (`docs/audit/raw/final-eval-r3/corpus/`), the round-4 corpus
  (`docs/audit/raw/final-eval-r4/corpus/`), the round-5 corpus
  (`docs/audit/raw/final-eval-r5/corpus/`), and the round-6 corpus
  (`docs/audit/raw/final-eval-r6/corpus/`), and zero exact-duplicate files
  within R7. Verified by hash BEFORE labeling; any collision is
  regenerated, not hand-edited to match a scanner. Method: every generated
  file carries a per-project header that is format-safe and
  semantics-preserving — a `# R7 project <pid>` comment line for Terraform,
  Bicep, YAML, and Dockerfiles, and a metadata section for JSON templates
  (ARM `"metadata": {"r7-project": pid}`, CloudFormation JSON
  `"Metadata": {"R7Project": pid}`). All files must parse (YAML with
  duplicate-top-level-key detection, JSON); zero duplicate Terraform
  resource declarations within any merged file.
- **Anti-memorization:** the R6 new classes carry over as established
  classes. At least 5 NEW concept classes never present in R3/R4/R5/R6
  (verified against the union of the R3/R4/R5/R6 generator concept lists
  and ground-truth class lists — see §3 Addendum C for the predeclared
  R7 classes), plus at least one new file-shape variant per format family
  (builder's choice, documented in `HANDOFF.md` — e.g. CloudFormation
  YAML templates, Bicep `.bicepparam` files, Pulumi `configuration:`
  blocks, K8s `CronJob` kinds). All new classes are injected at least
  once (forced-coverage queue in the generator).
- **Formats (exact counts, same as R6):** terraform 40, cloudformation 30,
  arm 15, bicep 15, pulumi 20 (10 `template:`-nested + 10 top-level),
  dockerfile 30, compose 25, kubernetes 35. Total 210.
- **Profiles (targets, same as R6):** vulnerable ~84 (40%), secure ~65
  (31%), mixed ~61 (29%). Difficulty: easy ~92 (44%), medium ~80 (38%),
  hard ~38 (18%). Clouds: target aws ~60, azure ~35, gcp ~1–2, multi ~24,
  none ~90 — exact cloud counts are recorded from the corpus, not forced;
  the report reconciles any deviation from target (R6's protocol §2 said
  aws 60 / gcp 1 while the corpus had aws 59 / gcp 2; the corpus counts
  govern).

## Addendum 1 — 2026-11-25: `ec2-imdsv1` is a renamed revival, not a first-ever class (before scanning)

**Before:** protocol §3 Addendum C listed `ec2-imdsv1` among the 7 new R7
classes "never present in R3/R4/R5/R6".

**Correction (disclosed by the corpus builder in `HANDOFF.md`, verified
against the R3/R4 class lists):** the IMDSv1 concept existed in R3/R4 as
`imdsv1` (absent R5/R6). The R7 name `ec2-imdsv1` is new, but the concept
is a renamed revival, not a first-ever class. The other 6 new classes
(`rds-snapshot-public`, `sqs-encryption-off`, `docker-run-as-root`,
`cloudtrail-off`, `alb-access-logs-off`, `s3-versioning-off`) were verified
absent from the R3/R4/R5/R6 class lists, so the §2 requirement of "at
least 5 NEW concept classes never present in R3/R4/R5/R6" is still met
(6 genuinely new). The `ec2-imdsv1` class keeps its firm judgment and its
rationale (explicit IMDSv1, SSRF/metadata-theft primitive); only its
novelty claim is corrected. No other protocol rule changes. This addendum
is filed before any scanning.
- **Labeling-blind authoring:** block patterns come from generic,
  industry-standard IaC security concepts. The generator author does not
  consult Aegis rule sources during authoring. (Residual risk: the same
  agent lineage authored R3/R4/R5/R6 blocks and knows the prior failure
  classes. Mitigation: new classes/shapes above + fresh labeling from code
  + §9 disclosure. This risk is stated, not hidden.)
- **Known R6 corpus defect to NOT repeat:** in R6 project r6068, SQS
  resources were nested under a CloudFormation `Mappings:` section instead
  of `Resources:` — a shared blind spot, not an adapter bug. The R7
  generator must place every injected resource under the format's real
  resource section. Any generator defect found after generation is fixed
  by regenerating with the same fixed seed and recorded as a numbered
  addendum (as R6 Addendum 1 did for the ARM merge bug), never by
  hand-editing corpus files.
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
  opening the first pass's file — the same limitation rounds 3–6 disclosed.
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
- **Adjudication criteria (fixed, same as rounds 2–6, PLUS the factual-FP
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
- **FACTUAL FP STANDARD (predeclared — the R5 lesson, retained from R6):**
  an unmatched scanner finding is FP **only if the flagged condition is
  factually absent or misread in the code**. A finding whose flagged
  condition factually holds — even if the labeler judges it immaterial,
  by-design, or not part of ground truth — is **LABEL-NOISE**, not FP.
  LABEL-NOISE is tracked separately, reported with its count, and **never
  counted as FP** in any precision or FP-rate computation. The primary
  precision is TP / (TP + FP_factual); a secondary "factual precision"
  (TP + LABEL-NOISE) / (TP + FP_factual + LABEL-NOISE) is reported
  alongside. The R5 carried standard (immaterial/by-design ⇒ FP) is
  explicitly NOT used in R7.
- **Agreement recorded:** raw agreement rate + Jaccard at (project, class)
  level, and Cohen's κ where computable. Pre-adjudication agreement is
  reported, not just post-adjudication 100%.
- **Scope:** firm concepts are critical/high only (same as R3–R6).
  Medium/low concepts recorded separately as soft concepts, not scored.

### Addendum C — R7 labeling-standard calibration (before labeling)

Calibrated against R6 Addendum C (which carries forward in full — the R6
firm/soft class judgments stand for R7 unless a class below says
otherwise):
- R6's adjudicated firm classes carry over as firm: `secret-hardcoded`,
  `db-public`, `redis-non-ssl`, `ecr-public-policy`, `k8s-run-as-root`,
  `sg-admin-public`, `apigw-no-auth`, `nsg-rdp-public`,
  `compose-db-port-published`, `k8s-cluster-admin-binding`,
  `ebs-snapshot-public`, `cloudsql-ssl-disabled`, `storage-unencrypted`,
  `compose-cap-add-sys-ptrace`, `k8s-host-namespace`, `k8s-cap-sys-admin`,
  `kafka-plaintext`, `docker-curl-pipe-shell`, `k8s-privileged`,
  `cloudfront-origin-http-only`, `compose-host-network`,
  `compose-privileged`, `compose-docker-sock`, `ecs-public-ip`,
  `alb-tls-old`, `elasticache-no-auth`, `opensearch-no-https`,
  `sqs-public-policy`, `sns-public-policy`, `lambda-invoke-public`,
  `neptune-no-encryption`, `efs-unencrypted`, `bigquery-public`,
  `az-mysql-public`, `az-vm-password-auth`, `az-storage-http-only`,
  `docker-multistage-secret`, `compose-host-pid`,
  `k8s-seccomp-unconfined`, `k8s-hostpath-writable`.
- R6's adjudicated SOFT classes stay soft: `docker-eol-base`,
  `k8s-hostpath-mount` (readOnly hostPath), `vm-encryption-at-host-disabled`,
  `weak-password-policy`, `acr-admin-user-enabled`, `dnssec-off`,
  `docker-healthcheck-disabled`, `docker-sshd`, `https-not-enforced`
  (`httpsOnly=false` on Web/Function Apps), `iam-weak-password-policy`,
  `gke-no-network-policy`, `az-webapp-no-https`, `cognito-weak-password`,
  `secrets-no-rotation`, `ecr-tag-mutable`, `docker-expose-sensitive-port`,
  `compose-run-as-root`, `k8s-lb-service`.
- The salient-weakness rule stands: incidental absences on otherwise-bare
  fixtures are NOT labeled (e.g. a `hostPath` fixture does not also get
  `k8s-no-security-context`); absence classes are labeled only where the
  resource is otherwise hardened on the other axes. Dockerfile ENV/ARG
  secrets ARE labeled firm `secret-hardcoded` (R4 deviation from R3,
  retained).
- New R7 classes, judged by the same bar (predeclared before labeling):

  | class | firm/soft | rationale |
  |---|---|---|
  | `ec2-imdsv1` | **firm** | explicit IMDSv1 (`http_tokens` optional) — SSRF/metadata-theft primitive, presence-based explicit config |
  | `rds-snapshot-public` | **firm** | public DB snapshot — data exposure (`ebs-snapshot-public` precedent) |
  | `sqs-encryption-off` | **firm** | explicit SSE disabled on a queue (`storage-unencrypted` precedent) |
  | `docker-run-as-root` | **firm** | explicit `USER root` in a Dockerfile (`k8s-run-as-root` precedent) |
  | `cloudtrail-off` | soft | absence of audit logging (detection control, absence-based) |
  | `alb-access-logs-off` | soft | absence of access logging (absence-based) |
  | `s3-versioning-off` | soft | absence of versioning/recovery control (absence-based) |

  The generator may add further new classes beyond these 7; any addition
  must be declared in writing (generator HANDOFF + a protocol addendum
  filed BEFORE labeling passes begin) with a firm/soft judgment by the
  same bar, and verified absent from the R3/R4/R5/R6 class lists.

## 4. Hygiene reclassification (labeling decision, NOT a detection change)

No Aegis code or rules are modified for this evaluation. The same 9
round-2 hygiene rule IDs are excluded from FP accounting for ALL scanners
equally (unchanged set — no additions after seeing R7 results):

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
| Aegis | Phase B merged build, 1,148 rules @ `ca5e7f0` | `/tmp/aegis-phaseb-r7` (SHA-256 in header) | `aegis scan <dir> --format=json`, default packs |
| Checkov | 3.3.26 | `~/workspace/.venv-checkov/bin/checkov` (SHA-256 `9cda52aeac4fefdfe3e72114d2e8b8a2da0902788bb61fef03ab52c473bbf1f2`, Python 3.12.3, verified working 2026-11-25) | `-d <dir> -o json --quiet`, default frameworks |

- Equivalent severity scope and exclusions across scanners; per-run
  commands recorded in each scanner's `RUNLOG.md`.
- **Accuracy:** 1 run per project per scanner.
- **Timing:** 5 timed runs per scanner per project on a fixed 30-project
  stratified subset (6 format groups × 5 projects, same interpretation
  as R6 §5 Addendum — see R6 RUNLOG), recorded in `TIMING.json`.
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
  mapping recorded in the adapted scorer; the classifier is the R6
  classifier carried over unchanged except for the new R7 classes, whose
  mappings are declared BEFORE scanner results are seen and recorded in a
  classifier changelog with justification — it must not add classes or
  move thresholds after results).
- TP/FP for unmatched findings come from FP adjudication (§7): adjudicated
  genuine findings (labeler-missed real issues) count as TP in the
  precision/FP-rate computation, exactly as in rounds 2–6. FN is counted
  against firm concepts only — and FN is scored against the sealed
  FN ground truth (`sealed/fn-manifest.json`, §2), not against the
  labelers' concepts alone: a firm concept in the FN manifest that no
  scanner matched is an FN even if labeling missed it; the QA
  completeness check (§2) reconciles any manifest/GT delta in writing.

### Format-scope rule (pre-registered)

When a scanner does not natively support a format, that is a **coverage
gap, disclosed — not silently penalized and not silently excused**:
- The **primary** metrics (used for the win condition) are computed over
  ALL firm concepts, as in rounds 2–6, so R7 is comparable to prior rounds.
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
  (no sampling — two scanners only). NOT delta adjudication: R7 gets a
  fresh full two-pass adjudication even though Phase B used a delta
  adjudication on R6.
- Fixed verdicts under the **factual standard (§3)**: TP / FP / HYGIENE /
  **LABEL-NOISE**, with a written justification per rule class (and per
  finding for context-sensitive rules). Adjudication is against the actual
  code, never against scanner reputation or prior-round verdicts: a rule
  that was FP in R6 is FP in R7 only if the R7 instances are FP on their
  own code facts. A finding whose flagged condition factually holds is
  LABEL-NOISE even if an R6 adjudication called the same family FP under
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
  2.5th/97.5th percentiles). Seed fixed (**20261126**) and recorded.
- **Pairwise differences:** bootstrap the difference (Aegis − Checkov)
  for F1 and FP rate; bold = CI excludes 0.
- **Speed:** median of per-project medians across 5 runs; declared faster
  iff median ratio > 2×.
- All analysis code lives under `docs/audit/raw/final-eval-r7/` and is
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
  recall authority, Aegis v2.3.0 vs Checkov 3.3.26 only. Verdict NOT YET:
  F1 lead +0.108 not decisive, FP rate Checkov 0.000 vs Aegis 0.026,
  speed 473×.
- Phase B (tuned-corpus measurement, NOT a blind round): F1 0.927,
  recall 0.863, TP 117, FN 16, FP 0 on the frozen R6 corpus — tuned
  numbers, must never be presented as blind evidence.
- R7: fresh corpus, fresh labels, factual FP standard, FN manifest as
  recall authority, Aegis Phase B merged build (1,148 rules) vs Checkov
  3.3.26 only. R7 is the only round that tests the Phase B build's
  generalization under the corrected standard.
The reconciliation will name the distinct causes — different corpora,
different scorers/GT scope, different FP standards, tuning — and will not
present any round's number as directly comparable to another's without
those caveats.

## 10. Artifacts to preserve

`docs/audit/raw/final-eval-r7/`: `gen_corpus_r7.py`, `corpus/`,
`MANIFEST.json`, `STATS.json`, `sealed/injection-plan.json`,
`sealed/fn-manifest.json`, `sealed/README.txt`, labeling passes +
adjudication log + inter-rater stats, `ground-truth.json`,
`scanner-output/<scanner>/` (raw outputs + `RUNLOG.md` + `TIMING.json` +
`FAILURES.json`), `labels/` (FP candidates + adjudications),
`score.py`, `stats.py`, `scores/`, `RUNLOG.md`, `HANDOFF.md`.
Aegis binary: `/tmp/aegis-phaseb-r7` (SHA-256 in header; rebuild command
recorded there for reproducibility).

## 11. Reporting

`docs/audit/32_FINAL_EVAL_R7_REPORT.md`: frozen commit SHA + binary
SHA-256, every metric with 95% CIs, per-criterion (a)/(b)/(c) PASS/FAIL
under the §1 decision rules, per-format and per-provider tables, coverage
matrix, LABEL-NOISE accounting, FN-manifest reconciliation, regressions
vs prior rounds, limitations (including the §3 labeler-independence
limitation and the Phase B tuning disclosure), the §9 reconciliation,
and verdict EARNED / NOT YET / INCONCLUSIVE. If inconclusive, stated
plainly with the statistical reason. No universal-superiority claim unless
the evidence supports the exact claim worded. The report number (32) is
the next free number after `31_EVAL_R7_PROTOCOL.md` (this file) and
`30_PHASE_B_MEASUREMENT.md`; if 32 is taken when the report is written,
use the next free number and note the change.
