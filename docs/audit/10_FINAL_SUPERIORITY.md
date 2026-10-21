# 10 — Final Superiority Verdict (Final Mission)

**Date:** 2026-10-12
**Branch:** `mission/final-superiority` (from `master@4e55443`)
**Final commit:** `bab6763`
**Rule registry:** 1,146 rules, 9 adapters

## 1. Mission summary

| Phase | Outcome |
|---|---|
| 1 — Test gaps | ✅ 355/355 Critical/High with true pos+neg evidence; quality gate rewritten from mention-counting to AST evidence verification |
| 2 — Scaling | ✅ Quadratic claim confirmed real but workload-specific (~cubic on dense reference graphs); 4 algorithmic defects fixed; now ~1.25 exponent, 7–116× faster; findings byte-identical |
| 3 — Blind evaluation | ✅ 60-project blind corpus, dual independent labelers (200 adjudicated concepts), 4 scanners pinned, predeclared win condition |
| 4 — Fix findings | ✅ Scale anomaly root-caused and fixed; FP tail investigated (legitimate by-design findings, not defects) |
| 5 — Verdict | **NOT YET** (this document) |

## 2. Win condition and verdict

**Predeclared (fixed before scoring):** Aegis wins iff (a) highest F1 on firm concepts, (b) lowest false-positive rate, (c) fastest median scan. All three required.

| Condition | Aegis | Best competitor | Result |
|---|---|---|---|
| (a) Highest F1 (firm) | **0.732** (0.743 post-fix est.) | Checkov 0.670 | ✅ ACHIEVED decisively |
| (b) Lowest FP rate | 9.0% | Checkov 9.1% | ❌ STATISTICAL TIE (±3pp margin) |
| (c) Fastest scan | **0.06 s** | Trivy 2.86 s | ✅ ACHIEVED decisively (48×) |

**Verdict: NOT YET.** Conditions (a) and (c) are decisive, unqualified wins. Condition (b) is not demonstrated: the 0.1pp gap is an order of magnitude below the measurement margin. Per the predeclared rule, no partial credit.

## 3. Head-to-head (blind corpus, 200 concepts)

| Scanner | Precision | Recall (firm) | F1 (firm) | Crit/High recall | FP rate | Median scan |
|---|---|---|---|---|---|---|
| **Aegis** 1,146 | 0.910 | 0.612 | **0.732** | **0.608** | 0.090 | **0.06 s** |
| Checkov 3.3.26 | 0.909 | 0.531 | 0.670 | 0.517 | 0.091 | 7.35 s |
| Trivy 0.74.0 | 0.908 | 0.388 | 0.543 | 0.392 | 0.092 | 2.86 s |
| KICS 2.1.20 | 0.812 | 0.423 | 0.557 | 0.433 | 0.188 | 72.7 s |

Per-format recall (firm): Aegis leads terraform (0.612), cloudformation (0.781), arm (0.517 tie), bicep (0.474 tie). Per-severity: Aegis leads critical (0.581), high (0.638), medium (0.655), low (0.524). Full data: `/tmp/eval-scores.json`, `/tmp/eval-report.md`, `/tmp/eval-raw/`.

## 4. What Phase 4 fixed

**Scale anomaly (real defect, fixed in `bab6763`):** 10 findings deterministically suppressed at full-corpus scale. Root cause: S3 companion-correlation helpers (`linkedBucketAddr`, `linkedTargetBucketAddr`, `policyBucketAddr`, `trailBucketAddr`, `logDeliveryBuckets`) resolved references to bare `type.name` addresses with no directory scope. When two scanned projects defined `aws_s3_bucket.logs`, project B's logging config suppressed findings on project A's bucket. Fix: directory-scoped correlation (`scopeKey` = source dir + address); refs resolve within the referring resource's directory (matching Terraform module semantics). Verified: proj-008 0→5 findings in full-corpus scan; 2 new regression tests; all existing S3/log-target tests pass.

**FP tail (investigated, not a defect):** Aegis's clean-project findings are overwhelmingly factually-correct hardening observations (WAF, deletion protection, detailed monitoring, descriptions). The labelers labeled clear misconfigurations only. Deleting by-design rules to win the FP race would be benchmark gaming, explicitly forbidden. No factual errors found in sampling.

## 5. Honest claim inventory

**EARNED (may be stated with scope):**
- "On the 2026-10-12 blind 60-project corpus (200 concepts), Aegis achieved the highest F1 (0.732) of the four tested scanners."
- "Aegis was the fastest scanner on every measured corpus (48× faster than the next on the blind corpus; 6–296× in prior benchmarks)."
- "355/355 Critical/High rules have positive+negative test evidence, verified by AST analysis in the quality gate."
- "The engine scales at ~1.25 exponent on reference-dense synthetic workloads to 16k resources."

**NOT YET (blocked):**
- Any "lowest false-positive rate" claim — statistical tie with Checkov.
- Any unqualified "No. 1 IaC scanner" claim — requires winning all three predeclared conditions.

## 6. What would close it

1. Reduce the noisy tail WITHOUT cutting detection: demote by-design hardening observations to explicitly-marked hygiene severity (some already are), so precision is measured on security findings only. Then re-run with 200+ adjudicated samples per scanner to shrink the margin.
2. Independent replication by a third party using the published corpus, labels, and rerun scripts.

## 7. Reproducibility

- Corpus: `/tmp/eval-corpus/` + `/tmp/eval-corpus/MANIFEST.json`
- Labels: `/tmp/eval-labels-A.json`, `/tmp/eval-labels-B.json`, `/tmp/eval-ground-truth.json`
- Scores: `/tmp/eval-scores.json`, `/tmp/eval-report.md`, `/tmp/eval-raw/RUNLOG.md`
- Code: branch `mission/final-superiority` @ `bab6763`; `go build -o aegis ./cmd/aegis/`; `go test ./...`; `./aegis quality-gate`

## 8. Limitations

- Single 60-project corpus; labelers were AI-assisted, not domain-expert humans; inter-rater agreement 56% at concept level (single-labeler concepts spot-verified valid).
- FP rates rest on sampled adjudication (±3pp margin).
- Scaling claim scoped to synthetic reference-dense Terraform; production variance possible.
- Bicep/ARM sample sizes small (n=19/29 firm concepts).
