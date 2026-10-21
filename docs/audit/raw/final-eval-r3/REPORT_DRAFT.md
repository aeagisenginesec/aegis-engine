# Round-3 Final Evaluation Report — Aegis (`mission/pulumi-recovery`)

**Date:** 2026-10-13
**Protocol:** `docs/audit/12_EVAL_R3_PROTOCOL.md` (pre-registered, frozen before execution)
**Candidate commit:** `41a8d77` — "Fix Pulumi adapter: support template:-nested layout, normalize Azure storage props, add 5 typemap entries"
**Frozen binary:** built via `go build -o /tmp/aegis-r3 ./cmd/aegis/` (`aegis doctor`: 1,146 rules loaded)
**Branch:** `mission/pulumi-recovery`
**Verdict:** _TBD_

## Win condition (unchanged from round 2)

Aegis wins iff ALL THREE hold vs Checkov, KICS, and Trivy:
- (a) **Highest F1** (firm concepts, adjudicated)
- (b) **Lowest FP rate** (adjudicated)
- (c) **Fastest** (median per-project scan time, 2× decision threshold)

No partial credit. No threshold changes after seeing results.

## 1. Corpus

_TBD — counts, format/difficulty/profile distribution_

- 210 NEW projects, ids `r3001`–`r3210`. Blind-authored from generic IaC security concepts; Aegis rule sources not consulted during authoring.
- Zero exact-duplicate files vs the round-2 corpus (`docs/audit/raw/final-eval/corpus/`).
- Pulumi: 20 projects (10 `template:`-nested + 10 top-level layouts).
- Generator: `docs/audit/raw/final-eval-r3/gen_corpus.py` (seed 20261013).
- Known corpus defects (documented, not hidden):
  - `r3049`/`r3050`: CloudFormation merge produced duplicate `Resources:` keys — surgically rewritten with proper merges (same blocks).
  - Duplicate resource names in merged multi-block projects (e.g. two `azurerm_key_vault.main` in `r3012`): both blocks' text present; labelers labeled the insecure instance.
  - `r3111`: duplicate `bastionSg` keys in Pulumi YAML — second renamed to `bastionSgRestricted`; re-labeled in both passes.
  - Single-file formats (dockerfile/compose): generator could select >1 block but only wrote `blocks[0]`; sealed injection plan corrected to `blocks_written`.

## 2. Ground truth

- Two sequential labeling passes (A, then B) by the same agent — B performed without opening A's file; both from code alone, no scanner output. (Single-agent limitation documented in §8.)
- Pre-adjudication key agreement: 143/149 (96.0%). All 6 disagreements were one pattern (SSH-open SGs: `sg-open-ssh` vs `sg-open-world`); adjudicated to `sg-open-ssh`.
- Post-adjudication: 149/149 (100%) at (project, class) level; +1 concept on `r3111` re-label → **150 firm (critical/high) concepts**.
- 62 soft (medium) concepts recorded separately (not scored).
- Classifier: round-2 `CLASS_RULES` + keyword fixes driven by labeler phrasing (pre-scanner-results), + new `eks-public-api` class. 0/150 concepts unclassified; 0 multi-class after fixes.
- QA: every injected firm concept present in GT (vocabulary alias `docker-secret`→`secret-hardcoded`; mediums excluded by design).

## 3. Scanners

_TBD — versions, configs, failures_

## 4. Results

_TBD — per-scanner metrics with 95% CIs, pairwise differences_

## 5. Per-criterion verdicts

_TBD_

- (a) F1: _TBD_
- (b) FP rate: _TBD_
- (c) Speed: _TBD_

## 6. Pulumi-specific acceptance

_TBD_

## 7. Limitations, exclusions, reproducible commands

_TBD_
