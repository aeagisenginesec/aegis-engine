# Phase B — before/after measurement on the frozen R6 corpus

**Status: measurement complete. All gates pass on the merged build.**
**Date:** 2026-11-25 ~16:20 UTC. **Lead:** Phase B lead (subagent session 10701489).
**Companions:** `28_FINAL_EVAL_R6_REPORT.md` (R6 baseline), `29_PHASE_B_GAP_LIST.md`
(gap list + priorities), raw data in `docs/audit/raw/final-eval-r6-phaseb/`
(copy of the R6 raw dir; the original `final-eval-r6/` is untouched).

## 1. Measurement build

- Branch `phase-b/measure-combined`, commit `ca5e7f0` — merges, no push, no merge
  to master:
  - `phase-b/pulumi-adapter-fix` (`5535d69`, Pulumi adapter fix)
  - `phase-b/rules-gap-fixes` (`d632587`, P0-1–P0-9, P1-1–P1-8, both FP fixes,
    AWS-004 evidence enrichment)
  - Both based on master `814a99b`.
- One merge conflict: `internal/adapter/pulumi/pulumi_phaseb_test.go` (add/add —
  both branches created the file). Resolved by combining both test sets:
  7 Pulumi-adapter tests + 4 stack-config (P1-7) tests = 11 tests, gofmt-clean,
  package tests pass.
- Binary: `/tmp/aegis-phaseb` (built from the merged branch, `CGO_ENABLED=0 go
  build`). `doctor`: all checks passed, **1,148 rules loaded** (was 1,140; +8 new).
- Verification on the merged branch: `go test ./...` — **32 packages ok, 0 FAIL**;
  `go vet ./...` — clean. Quality gate: see §7.

## 2. Method (frozen protocol, delta adjudication)

- Copied `docs/audit/raw/final-eval-r6/` → `docs/audit/raw/final-eval-r6-phaseb/`;
  pointed only the copy's `sweep_r6.py` at `/tmp/aegis-phaseb`. Checkov 3.3.26
  outputs, labels, sealed FN manifest, and scorer code are byte-identical to R6.
- Sweep: **210/210 accuracy ok**, timing 30 projects × 5 runs in 4 s total.
- Re-scored with the frozen `score_r6.py` (classifier unchanged — NO scorer
  changes, per the Phase B rules). `stats_r6.py` re-run for bootstrap CIs and
  the per-criterion decision block.
- FP adjudication is a **delta adjudication** (not the full R6 two-pass process):
  the copy's `labels/fp-adjudicated-aegis.json` carries over **1,366** old verdicts
  for findings still present, and adds **75** new verdicts for newly-unmatched
  findings — 13 TP (classifier-miss, duplicate evidence of a TP'd GT concept,
  same convention as R6's DOCKER-021 TPs), 54 LABEL-NOISE, 8 HYGIENE (per-rule
  verdicts follow R6's own treatment of those rules). The 2 old FP records drop
  out because the findings no longer exist. FP = 0 rests on the factual review
  of all 115 new findings (§5), not on a fresh full adjudication.

## 3. Headline — before/after (frozen scorer, same 210 projects, same 141 GT / 117 manifest-firm)

| Metric | R6 (v2.3.0) | Phase B (merged) | Checkov 3.3.26 (unchanged) |
|---|---|---|---|
| TP (GT 141) | 76 | **117** | 47 |
| TP_fn (manifest 117) | 60 | **101** | 46 |
| FN | 57 | **16** | 71 |
| FP (adjudicated) | 2 | **0** | 0 |
| Precision | 0.974 | **1.000** [1.000, 1.000] | 1.000 |
| Recall | 0.513 | **0.863** [0.793, 0.923] | 0.393 |
| **F1** | **0.672** [0.583, 0.747] | **0.927** [0.885, 0.960] | **0.564** [0.467, 0.654] |
| FP rate | 0.026 | **0.000** [0.000, 0.000] | 0.000 |
| Findings | 1,445 | 1,559 | — |
| Unmatched | 1,368 | 1,441 | 1,127 |
| Median scan time | 0.0101 s | **0.0102 s** | 4.7603 s (468×) |

- **Pairwise F1 difference (Aegis − Checkov): [+0.266, +0.467], mean +0.363.**
  The 95% CI is entirely above 0.
- **Pairwise FP difference (Checkov − Aegis): [0.000, 0.000].** Genuine tie.
- **On formats Checkov supports (165 projects, coverage-adjusted): Aegis F1 0.927
  vs Checkov 0.667.** The R6 caveat is gone — the lead no longer comes only from
  Pulumi + Compose.

## 4. Per-criterion verdicts (pre-registered all-three win condition)

- **(a) Highest F1: PASS.** Pairwise CI [+0.266, +0.467] entirely above 0.
  (R6: FAIL, CI [−0.024, +0.238].)
- **(b) Lowest FP rate: FAIL — genuine tie.** Both scanners 0.000 (Aegis 0 FPs,
  Checkov 0 FPs). The pre-registered rule requires the *lowest* FP rate; a 0–0
  tie is not the lowest, per the R4 precedent (Aegis failed (b) there on a
  genuine KICS tie). The FP *deficit* is closed (2 → 0), but the criterion as
  written can only be won on a corpus where Checkov makes ≥1 FP and Aegis makes
  0. Flag for R7: this criterion is un-winnable by FP on any corpus where both
  scanners are factually perfect.
- **(c) Fastest: PASS.** 0.0102 s vs 4.7603 s — 468×, far above the 2× threshold.

**Overall: NOT YET — 2 of 3 criteria.** The failure mode changed completely:
R6 failed (a) on a CI containing 0 and (b) with Checkov ahead on the point
estimate. Phase B passes (a) decisively and (c), and (b) is now a 0–0 tie
instead of a 2.6pp deficit.

## 5. What flipped, what remains

**41 of 57 Aegis FNs flipped to TP** (frozen classifier, no scorer changes):
CFN apigw-no-auth ×3, CFN sqs-public-policy ×3, CFN db-public ×4, CFN
ecr-public-policy ×1, CFN sns-public-policy ×1, CFN kafka-plaintext ×1,
CFN ebs-snapshot-public ×1, ARM az-mysql-public ×1, ARM az-vm-password-auth ×1,
TF gcp-function-public ×2, TF kafka-plaintext ×1, TF ebs-snapshot-public ×1,
Pulumi apigw-no-auth ×1, sqs-public-policy ×1, ecr-public-policy ×1,
secret-hardcoded ×5, Dockerfile docker-multistage-secret ×4, secret-hardcoded
×4, Compose compose-db-port-published ×3, K8s k8s-cap-sys-admin ×2.
Full pair list in `scores-auto.json` (tp_fn_by_class) and §5 of this report's
source data; per-pair: see the measurement script output in the run log.

**16 FNs remain** — all classifier near-misses except one corpus defect:
- secret-hardcoded ×4 — r6014 (TF, AWS-534), r6124/r6133 (Dockerfile,
  DOCKER-021), r6188 (K8s, K8S-026). Findings exist; classifier doesn't map
  the titles.
- sg-admin-public ×3 — r6017 (TF), r6043/r6056 (CFN, AWS-004). The port-range
  evidence enrichment did not change the classifier mapping (it matches on
  title, not evidence).
- az-storage-http-only ×5 — r6074/r6079/r6080/r6084 (ARM), r6095 (Bicep,
  AZURE-026).
- az-sql-weak-tls ×3 — r6086/r6095/r6099 (Bicep, AZURE-105).
- sqs-public-policy ×1 — r6068 (CFN). **Corpus defect, not an engine gap:**
  its SQS resources are indented under `Mappings:`; both tools miss it
  (shared blind spot). Fix upstream in the corpus generator; do not tune the
  adapter to mine `Mappings:` for resources.

**Classifier-miss-recovered recall (sensitivity): Aegis 0.991** (101 + 15
recovered; only r6068 has no finding at all). Checkov 0.581. The engine now
finds all but one pair; the remaining gap is the classifier's title matching,
not detection.

**FP delta (factual review of all 115 new findings, 2 removed):**
- Removed: exactly the 2 known FPs — K8S-029 on r6176 (1→0), DOCKER-005 on
  r6139 (1→0). K8S-017 still fires on r6176. Nothing else removed (no lost TPs).
- New by rule: AWS-515/521 ×8 each (ECR repos now visible via Pulumi typemap —
  factually correct absent attributes, LABEL-NOISE on secure-profile projects);
  SC-010 ×7; DOCKER-021 ×6; AWS-844/403 ×4 each; AWS-344 ×4; AWS-011 ×4;
  DOCKER-038 ×4; DOCKER-003 ×4; COMPOSE-010 ×3; GCP-295 ×2; AWS-345/808 ×2
  each; AWS-408 ×2; AZURE-* ×2 each on r6101/r6105 (22 rules × 2 projects —
  the now-visible WebApp; TF parity of the rule-ID set verified by the Pulumi
  lead); K8S-033 ×2; AWS-860, AWS-343, AZURE-315, AZURE-024, AZURE-316 ×1 each.
- **0 new FPs.** Every new finding fires on a real attribute; the ones that
  flip GT pairs are confirmed TPs, the rest are LABEL-NOISE/HYGIENE by R6's
  own per-rule treatment.

## 6. Per-format F1 (Aegis before → after; Checkov now)

| Format | Aegis R6 | Aegis Phase B | Checkov |
|---|---|---|---|
| Terraform | 0.864 | **0.958** | 0.718 |
| CloudFormation | 0.385 | **0.923** | 0.800 |
| ARM | 0.000 | 0.500 | 1.000 |
| Bicep | 0.545 | 0.667 | 0.769 |
| Pulumi | 0.556 | **1.000** | 0.000 (skip) |
| Compose | 0.857 | **1.000** | 0.000 (skip) |
| Dockerfile | 0.154 | **0.900** | 0.000 |
| Kubernetes | 0.900 | **0.976** | 0.500 |

Aegis now leads on TF, CFN, K8s, Pulumi, Compose, Dockerfile; trails on ARM
(0.500 vs 1.000) and Bicep (0.667 vs 0.769) — both gaps are the AZURE-026/105
classifier near-misses, not missing detections.

## 7. Quality gate on the merged build

- `go test ./...`: 32 packages ok, 0 FAIL. `go vet ./...`: clean.
- `aegis quality-gate` on the merged binary (`/tmp/aegis-phaseb`): **PASS** (exit 0,
  ~11 min run, completed 16:18 UTC):
  - precision 100.0% (TP 355, FP 0, FN 0, threshold ≥95%)
  - recall 100.0% (TP 355, FP 0, FN 0, threshold ≥90%)
  - rule-coverage 363/363 critical/high rules with pos+neg evidence
  - performance median 22.8 ms, p95 74.3 ms (threshold p95 ≤ 500 ms; 11 runs on
    vuln-200)
  - parser-safety 15/15 explicit
  - `QUALITY GATE: PASS — release may proceed`

## 8. Caveats (read before quoting any number)

- **Tuned against R6.** Every new rule was built from R6 FN evidence, so these
  are tuned-corpus numbers, not blind results. A fresh blind round (R7) is
  required to confirm any gain — the R6 corpus is the measuring stick, not the
  training set, and the +0.255 F1 jump will almost certainly shrink on fresh
  code (the R6-specific tail — e.g. the 22-rule WebApp burst on r6101/r6105 —
  will not repeat at the same density).
- **Delta adjudication.** FP = 0 comes from §2's delta adjudication (1,366
  carried R6 verdicts + 75 new verdicts by the Phase B lead), not a fresh
  full two-pass adjudication. The FP conclusion is robust (2 known FPs
  verified gone; 115 new findings factually reviewed), but R7 should get a
  full adjudication pass.
- **Classifier, not engine, is now the bottleneck.** 15 of the 16 remaining FNs
  have findings the classifier doesn't map. Fixing them by retitling rules to
  match the classifier's keywords is legitimate rule work, but it is tuning
  the engine to the scorer — disclose it as such in R7 if done.

## 9. What remains for Phase C

1. **R7 fresh blind eval** (210 new projects, same frozen protocol) — the only
   way to confirm the Phase B gain and to earn criterion (b), which needs a
   corpus where Checkov makes ≥1 FP and Aegis makes 0.
2. **ARM/Bicep near-misses (8 pairs):** AZURE-026 (az-storage-http-only) and
   AZURE-105 (az-sql-weak-tls) titles/keywords don't map in the classifier.
   Engine fires; scorer doesn't count. Options: retitle to carry the class
   keywords (disclose as scorer-tuning), or fix the classifier mapping (scorer
   change — needs protocol sign-off, not a silent fix).
3. **sg-admin-public near-miss (3 pairs):** AWS-004 title doesn't map; evidence
   enrichment didn't help (classifier matches on title). Same options as (2).
4. **secret-hardcoded near-miss (4 pairs):** AWS-534 (TF user_data), DOCKER-021,
   K8S-026 titles don't carry the `hardcoded` keyword. Same options as (2).
5. **r6068 corpus defect:** fix the generator so SQS resources aren't nested
   under `Mappings:` (shared blind spot for both tools).
6. **v2.4.0 feature work** (deferred from v2.3.0): SBOM, IAM kill-chain links,
   full NotAction/NotResource, attack-path remediation consistency, native
   SIEM/SOAR webhook, benchmark-file authority — none of which the R6/R7
   detection numbers measure.
7. **Merge/push decision:** branches `phase-b/pulumi-adapter-fix` (`5535d69`),
   `phase-b/rules-gap-fixes` (`d632587`), and `phase-b/measure-combined`
   (`ca5e7f0`) are all local-only. No merge, no push without the user's
   explicit approval; push needs his token via the secure form.
