# 11 — Final Evaluation Round 2: Report

**Date:** 2026-10-13
**Branch:** `mission/final-eval-round2` (from `ddb9347`)
**Candidate commit (frozen):** `ddb934766e8b0199172a4b9f60049bd268932513`
**Binary:** `docs/audit/raw/final-eval/aegis-frozen`
(`go build ./cmd/aegis` from the frozen commit;
sha256 `9ae868d9d244361be46e074c1c74601b17198b2378605492171660dd2633738d`;
1,146 rules)
**Protocol:** `docs/audit/11_EVAL_PROTOCOL.md` (frozen before execution;
Addendum A documents the /tmp wipe and path relocation — no
methodological change)
**Verdict: NOT YET.**

## 1. What this round decided

The prior round (60 projects) left one question open: the Aegis-vs-Checkov
false-positive-rate tie (9.0% vs 9.1%, ±3pp). This round ran 205 fresh blind
projects with full (not sampled) FP adjudication for the decision pair and
cluster-bootstrap statistics to answer it — and to test the full win
condition against all four scanners.

**The head-to-head question is answered:** Aegis beats Checkov decisively on
all three criteria — F1 +0.122 (95% CI [+0.086, +0.159]), FP rate −0.072
(CI [−0.104, −0.042]), speed 114×.

**The superiority claim is not earned:** the win condition requires Aegis to
beat *all* scanners on *all three* criteria. Trivy — a narrower,
high-precision scanner — has a decisively lower FP rate than Aegis
(0.342 vs 0.733, difference CI [−0.483, −0.302]) and a numerically higher F1
(0.382 vs 0.367; the difference is not statistically significant, but the
win condition requires Aegis to hold the highest F1, which it does not).

## 2. Head-to-head results (205 projects, 416 firm concepts)

95% CIs are cluster-bootstrap by project (10,000 resamples; sampling unit =
project). FP rates use adjudicated verdicts: full adjudication of every
unmatched finding for Aegis (1,355) and Checkov (1,059); seeded stratified
400-samples for KICS and Trivy (two-level bootstrap with binomial redraw).

| Scanner | Precision | Recall | F1 | FP rate | FN rate | Median scan |
|---|---|---|---|---|---|---|
| **Aegis** 1,146 | 0.267 [0.227, 0.310] | **0.587** [0.534, 0.638] | 0.367 [0.323, 0.411] | 0.733 [0.690, 0.773] | 0.413 | **0.056 s** |
| Checkov 3.3.26 | 0.195 [0.162, 0.230] | 0.329 [0.273, 0.387] | 0.245 [0.207, 0.283] | 0.805 [0.770, 0.838] | 0.671 | 6.36 s |
| KICS 2.1.20 | 0.107 [0.087, 0.127] | 0.221 [0.180, 0.264] | 0.144 [0.119, 0.170] | 0.893 [0.873, 0.913] | 0.779 | 28.9 s |
| Trivy 0.74.0 | **0.658** [0.568, 0.750] | 0.269 [0.222, 0.318] | **0.382** [0.326, 0.437] | **0.342** [0.250, 0.432] | 0.731 | 6.60 s |

Pairwise differences (95% CI of the difference, cluster bootstrap):

| Comparison | F1 difference (Aegis − other) | FP-rate difference |
|---|---|---|
| Aegis − Checkov | **+0.122 [+0.086, +0.159]** | **−0.072 [−0.104, −0.042]** (Checkov − Aegis) |
| Aegis − KICS | **+0.223 [+0.181, +0.265]** | **−0.161 [−0.201, −0.123]** (KICS − Aegis) |
| Aegis − Trivy | −0.015 [−0.073, +0.042] | **+0.392 [+0.302, +0.483]** (Trivy − Aegis) |

Bold = CI excludes 0 (decisive).

## 3. Per-criterion verdicts (fixed decision rules, protocol §8)

**(a) Highest F1 — FAIL.**
Aegis F1 0.367 [0.323, 0.411]; Trivy 0.382 [0.326, 0.437] is numerically
higher. The bootstrap CI of the difference ([−0.073, +0.042]) contains 0,
so the gap is not statistically significant — but the win condition
requires Aegis to *hold* the highest F1, which it does not. Aegis does
decisively beat Checkov (+0.122) and KICS (+0.223) on F1.

**(b) Lowest FP rate — FAIL.**
Trivy FP rate 0.342 [0.250, 0.432] vs Aegis 0.733 [0.690, 0.773]; the
(Trivy − Aegis) difference CI [−0.483, −0.302] lies entirely below 0 —
Trivy is decisively lower. Against the prior round's rival, Aegis wins:
(Checkov − Aegis) = +0.072 [+0.042, +0.104], entirely above 0 — the
predeclared FP tie is broken in Aegis's favor. But the win condition
demands the lowest rate among *all* scanners.

**(c) Fastest — PASS (decisive).**
Median of per-project medians (30-project stratified subset; Aegis/Checkov/
Trivy 5 runs per project, KICS single-run documented deviation):
Aegis 0.056 s vs Checkov 6.36 s (**114×**), Trivy 6.60 s (**118×**),
KICS 28.9 s (**519×**). All ratios far exceed the 2× decision threshold.

**Overall: 1 of 3 criteria → verdict NOT YET.** No partial credit per the
predeclared rule.

## 4. Where Aegis wins and where it loses

**Recall — Aegis leads decisively and broadly.**
Recall 0.587 vs Checkov 0.329, KICS 0.221, Trivy 0.269. Aegis leads recall
in every severity band (high 0.511 / medium 0.624 / low 0.623 — best in all
three) and in 4 of 8 covered formats (terraform, kubernetes, compose,
mixed). Per-format F1 leaders: Aegis 4 (terraform 0.268, kubernetes 0.660,
compose 0.571, mixed 0.546), Trivy 3 (cloudformation 0.416, arm 0.634,
docker 0.598), Checkov 1 (bicep 0.317). No scanner produced any finding on
the 15 Pulumi projects (native skip for Checkov/KICS/Trivy; Aegis's Pulumi
adapter emitted zero findings — a coverage gap, §7).

**Precision — the FP tail is the whole story.**
Aegis precision 0.267: 670 of 1,324 adjudicated unmatched findings were
genuine false positives. The tail is dominated by low-value rules:
`DOCKER-018` no STOPSIGNAL (39), `DOCKER-017` no maintainer label (39),
`K8S-015` readiness probe (22 — see note below), `AWS-673` no IAM
description (19), `DOCKER-022` COPY of build context (16), `AZURE-058`
VNet without custom DNS (15), `AZURE-057` VNet without DDoS plan (15),
`AWS-601` S3 lifecycle (14), plus hundreds more. Trivy, by contrast,
emits 811 findings with an 8.6% adjudicated FP fraction (33/383) —
narrower coverage, far fewer false alarms.

Note on probes/healthchecks: the first FP-adjudication pass wrongly marked
factually-correct availability/detection findings as FP ("not a security
control"), contradicting the protocol's explicit "(including availability
and detection controls)" and the ground truth's own 42 healthcheck / 19
probe firm concepts. 195 findings were re-adjudicated with the correct
criterion (101 + 96 flipped to TP; details in RUNLOG.md). The numbers
above reflect the corrected adjudication.

**Speed — not close.** 0.056 s median; 14.9 MB peak RSS per scan.

## 5. Regressions vs the prior round (read carefully)

Absolute numbers moved a lot; almost all of the movement is measurement,
not product:

| | Prior round (60 proj) | This round (205 proj) |
|---|---|---|
| Aegis F1 | 0.732 | 0.367 |
| Checkov F1 | 0.670 | 0.245 |
| Trivy F1 | 0.543 | 0.382 |
| Aegis FP rate | 0.090 | 0.733 |
| Aegis median scan | 0.06 s | 0.056 s |

Why the drop: (1) the matcher changed from resource-name matching to
(project, condition-class) min-counting — harsher on scanners that emit
multiple findings per class; (2) FP adjudication went from a small sample
(±3pp) to full adjudication of 1,355 Aegis findings, fully exposing the FP
tail the prior round under-measured; (3) a fresh, denser 205-project
corpus. The *rankings* are what the win condition uses, and they are
comparable: Aegis still beats Checkov on F1 and speed, and now beats it on
FP rate too. What changed vs the prior round is Trivy: its high-precision
profile (few, accurate findings) scores much better under full
adjudication than under the prior round's sampling.

## 6. Unresolved issues and limitations

1. **Bicep for-comprehension OOM (real defect, frozen candidate).**
   `c043` and `c049` (1.6 KB Bicep files with `for` comprehensions) drive
   the scanner to ~3.7 GB RSS in 30 s; the kernel OOM-killer SIGKILLs the
   scan (exit −9). Same family as the pre-wipe corpus's `c045`. Scored as
   failures, never zero-filled. Fixing is product work for after the
   evaluation, not part of it.
2. **Pulumi adapter gap.** Zero Aegis findings on all 15 Pulumi YAML
   projects (all scanners natively skip Pulumi; Aegis claims an adapter).
3. **Adjudicator strictness variance.** Aegis's five FP shards ranged from
   45% to 76% FP verdicts (interleaved across projects, so partly
   finding-mix, partly strictness). The cluster bootstrap captures
   project-level variation but not adjudicator-level variation; the
   aggregate FP fraction (670/1,324 = 50.6%) is the best estimate.
4. **Ground-truth incompleteness.** Labelers found 416 firm concepts;
   adjudicators later judged 1,435 additional scanner findings genuine
   (labeler-missed). TP/FN are counted against the 416 firm concepts only
   (protocol §7; prior-round consistent). An additive sensitivity analysis
   (TP-missed added to TP) gives Aegis F1 0.654 vs Trivy 0.804 — same
   verdict (NOT YET).
5. **KICS timing deviation** (documented in protocol Addendum A):
   single-run-per-project instead of 5 runs. Cannot flip criterion (c).
6. **Infrastructure incidents.** /tmp wiped 2026-10-12 ~23:30 UTC
   (full rebuild with a fresh corpus; see protocol Addendum A); daemon
   restarts killed two sweeper workers mid-run (resumed from persistent
   partial outputs). All final artifacts live under
   `docs/audit/raw/final-eval/` (persistent).
7. **One classless concept** (`t068`, overly-broad internal CIDR) — counts
   as FN for all scanners equally.

## 7. What would earn the claim

The gap is precision, not recall or speed. To earn the claim under the
same win condition, Aegis would need roughly: FP rate below Trivy's
(~0.34, i.e. cut ~370 of the 670 adjudicated FPs) while holding recall —
which means retiring or demoting the noisy tail (`DOCKER-017/018`,
`AWS-673`, `AZURE-057/058`, `DOCKER-022`, `AWS-601`, and the long tail of
similar rules), as the prior round already recommended. That is genuine
product-quality work, not benchmark tuning — but under the standing
constraint it must be done as a product decision with its own validation,
not as a reaction to this scoreboard. The Bicep OOM and Pulumi gap are
independent defects to fix regardless.

## 8. Method and reproducibility

- **Corpus:** 205 fresh blind projects,
  `docs/audit/raw/final-eval/corpus/` (`t001–t070` terraform,
  `c001–c070` cloudformation/arm/bicep/pulumi, `k001–k065`
  docker/kubernetes/compose/mixed) + `MANIFEST.json` (profile 40/25/35
  vuln/secure/mixed; difficulty 29/45/26 easy/medium/hard).
- **Labeling:** 8 independent labelers (2 per chunk), blind to scanners and
  to the manifest; 748 raw concepts → adjudication → **416 firm concepts**
  (inter-rater: raw agreement 80.5%, Jaccard 0.708, severity κ 0.68).
  `labels/ground-truth.json`, `labels/adjudication-log.json`,
  `labels/inter-rater.json`.
- **Scanners:** Aegis @ `ddb9347` (frozen binary sha256 `9ae868d9…`);
  Checkov 3.3.26 (`~/workspace/.venv-checkov/bin/checkov`, default
  frameworks); KICS 2.1.20 (5 batched scans, `--queries-path
  ./assets/queries`); Trivy 0.74.0 (`trivy config`, misconfig-only).
  Raw outputs: `scanner-output/<scanner>/` (+ `EXITCODES.json`,
  `FAILURES.json`, `TIMING.json`, `RUNLOG.md` per scanner).
- **Scoring:** `score.py` (normalized-pattern taxonomy, (project, class)
  min-counting, 9 hygiene rule IDs excluded for all scanners);
  `fp_sample.py` (seed 20261013; full adjudication for Aegis/Checkov,
  400-samples for KICS/Trivy); `stats.py` (cluster bootstrap by project,
  B=10,000; two-level binomial redraw for sampled FP fractions).
  FP adjudication: 12 shard workers + 3 re-adjudication passes, fixed
  TP/FP/HYGIENE/UNCERTAIN criteria; all verdicts with per-finding
  justifications in `labels/fp-shards/`.
- **Rerun:** `python3 score.py && python3 fp_sample.py && python3
  split_fp_shards.py` (then adjudicate shards per the briefs in RUNLOG.md),
  `python3 stats.py`. Timing: `timing_harness.py` +
  `timing-subset.json`. Scanner sweep commands are in each
  `scanner-output/<scanner>/RUNLOG.md`.

## 9. Bottom line

Aegis is the fastest scanner here by two orders of magnitude, finds more
real issues than any rival (recall 0.587, best in every severity band),
and now beats Checkov — the prior round's sticking point — on false-positive
rate too (+7.2pp, decisive). But "outperforms **all** IaC scanners" is not
earned: Trivy is decisively less noisy (FP rate 0.342 vs 0.733) and holds a
narrow F1 edge (0.382 vs 0.367). The claim fails on precision, and the fix
is product work: quiet the FP tail. **Verdict: NOT YET.**
