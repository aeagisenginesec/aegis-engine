# Round-3 Final Evaluation Report — Aegis (`mission/pulumi-recovery`)

**Date:** 2026-10-13
**Candidate commit:** `41a8d77` — "Fix Pulumi adapter: support template:-nested layout, normalize Azure storage props, add 5 typemap entries"
**Frozen binary:** `go build -o /tmp/aegis-r3 ./cmd/aegis/` (`aegis doctor`: 1,146 rules loaded)
**Branch:** `mission/pulumi-recovery`
**Verdict:** **NOT YET**

## Win condition

Aegis wins iff ALL THREE hold vs Checkov 3.3.26, KICS 2.1.20, and Trivy 0.74.0:
- (a) **Highest F1** (firm concepts, adjudicated)
- (b) **Lowest FP rate** (adjudicated)
- (c) **Fastest** median per-project scan time (2× decision threshold)

No partial credit. No threshold changes after seeing results.

## 1. Corpus

**210 NEW projects** (ids `r3001`–`r3210`), blind-authored from generic IaC security concepts without consulting Aegis rule sources.

| Format | Count | Profile | Count | Difficulty | Count |
|---|---|---|---|---|---|
| terraform | 40 | vulnerable | 87 | easy | 92 |
| cloudformation | 30 | mixed | 59 | medium | 80 |
| arm | 15 | secure | 64 | hard | 38 |
| bicep | 15 | | | | |
| pulumi | 20 (10 `template:`-nested + 10 top-level) | | | | |
| dockerfile | 30 | | | | |
| compose | 25 | | | | |
| kubernetes | 35 | | | | |

- Zero exact-duplicate files vs the round-2 corpus (`docs/audit/raw/final-eval/corpus/`).
- Generator: `docs/audit/raw/final-eval-r3/gen_corpus.py` (seed 20261013).
- **Known corpus defects** (documented, not hidden):
  - `r3049`/`r3050`: CloudFormation merge produced duplicate `Resources:` keys — surgically rewritten with proper merges (same blocks).
  - `r3111`: duplicate `bastionSg` keys in Pulumi YAML — second renamed `bastionSgRestricted`; re-labeled in both passes.
  - Duplicate resource names in merged multi-block projects (e.g. two `azurerm_key_vault.main` in `r3012`): both blocks' text present; labelers labeled the insecure instance.
  - Single-file formats (dockerfile/compose): generator could select >1 block but only wrote `blocks[0]`; injection plan corrected to `blocks_written`.

## 2. Ground truth

- **Two sequential labeling passes** (A, then B) by the same agent — B performed without opening A's file; both from code alone, no scanner output. (Single-agent limitation disclosed in §7.)
- Pre-adjudication key agreement: **143/149 (96.0%)**. All 6 disagreements were one pattern (SSH-open SGs: `sg-open-ssh` vs `sg-open-world`); adjudicated to `sg-open-ssh`.
- Post-adjudication: 100% at (project, class) level; +1 concept on `r3111` re-label → **150 firm (critical/high) concepts** across 122 projects (88 projects have 0 firm concepts).
- 62 soft (medium) concepts recorded separately (not scored).
- **Classifier** (`score.py`): round-2 `CLASS_RULES` + keyword fixes driven by labeler phrasing (pre-scanner-results), + new `eks-public-api` class. Post-Aegis-results, pre-final-scoring: 10 finding-title→existing-class mappings added (documented in `labels/CLASSIFIER_CHANGELOG.md`; no new classes, no threshold changes). Final: 0/150 concepts unclassified, 0 multi-class, A/B agreement holds.
- QA: every injected firm concept present in GT (vocabulary alias `docker-secret`→`secret-hardcoded`; mediums excluded by design).

## 3. Scanners

| Scanner | Version | Config | Notes |
|---|---|---|---|
| Aegis | frozen `/tmp/aegis-r3` (1,146 rules) | `accuracy` + 5 timed runs | 210/210 parsed (exit ≤1) |
| Checkov | 3.3.26 | `-d <dir> -o json --quiet`, 5 timed runs | 210/210 completed |
| KICS | 2.1.20 | `scan -p <dir> --queries-path ./assets/queries`, single full-corpus run + 30×1 timing | 1×202s accuracy run; 30 single-run timings |
| Trivy | 0.74.0 | `config --skip-version-check --skip-check-update --format json`, 5 timed runs | 210/210 completed |

**Native coverage gaps** (disclosed):
- Checkov: no misconfiguration checks for Pulumi or compose (secrets framework only); scans TF/CFN/ARM/Bicep/Dockerfile/K8s.
- Trivy: no checks for Pulumi, compose, or Bicep; scans TF/CFN/ARM/Dockerfile/K8s.
- KICS: scans all formats (broadest coverage).

**Timing methodology:** 30-project stratified subset (5 per format group + Pulumi both layouts), 5 timed runs per scanner per project (KICS: single runs, documented deviation as in round 2). Median of per-project medians.

## 4. Results

### Per-scanner metrics (point estimate + 95% cluster-bootstrap CI, 10,000 resamples by project)

| Scanner | F1 | Precision | Recall | FP rate | FN rate |
|---|---|---|---|---|---|
| **Aegis** | **0.733** [0.674, 0.790] | 0.686 | 0.787 | 0.314 [0.236, 0.389] | 0.213 |
| Checkov | 0.318 [0.243, 0.394] | 0.500 | 0.233 | 0.500 [0.317, 0.635] | 0.767 |
| KICS | 0.477 [0.388, 0.562] | 1.000 | 0.313 | 0.000 [0.000, 0.000] | 0.687 |
| Trivy | 0.301 [0.219, 0.383] | 0.446 | 0.227 | 0.554 [0.360, 0.691] | 0.773 |

### Pairwise differences (Aegis − competitor, 95% CI)

| Comparison | F1 difference | FP-rate difference |
|---|---|---|
| Aegis − Checkov | **+0.416** [+0.333, +0.497] ✓ | **−0.179** [−0.305, −0.025] ✓ (Aegis lower) |
| Aegis − KICS | **+0.257** [+0.153, +0.359] ✓ | **+0.313** [+0.236, +0.389] ✗ (KICS lower) |
| Aegis − Trivy | **+0.433** [+0.338, +0.526] ✓ | **−0.232** [−0.397, −0.035] ✓ (Aegis lower) |

### Timing (median per-project scan time)

| Scanner | Median | Ratio vs Aegis |
|---|---|---|
| **Aegis** | **0.0119s** | 1× |
| Trivy | 2.78s | 234× |
| Checkov | 4.07s | 342× |
| KICS | 8.93s | 752× |

All ratios exceed the 2× decision threshold.

### FP adjudication summary

| Scanner | Unmatched | Adjudicated | TP (genuine) | HYGIENE | FP |
|---|---|---|---|---|---|
| Aegis | 2,028 | 2,028 (full) | 1,743 | 231 | **54** |
| Checkov | 1,376 | 1,376 (full) | 1,093 | 248 | **35** |
| KICS | 2,051 | 400 (stratified sample) | 279 | 121 | **0** |
| Trivy | 1,073 | 400 (stratified sample) | 293 | 95 | **12** |

Aegis's 54 FPs: 15× unrestricted egress (by-design), 12× SSE on intentionally-public buckets, 12× PAB on intentionally-public buckets, 8× root-user in multi-stage build stages, 7× gcr.io misclassified as untrusted.

KICS's 0 FPs in the 400-sample: KICS queries are precise; its unmatched findings are genuine hardening controls (TP) or non-security pedantry (HYGIENE). The [0.000, 0.000] CI reflects zero FP events in the sample; even allowing for sampling uncertainty, KICS's FP rate is decisively below Aegis's.

## 5. Per-criterion verdicts

- **(a) Highest F1: PASS** ✓ — Aegis F1=0.733 exceeds all three competitors with CIs entirely above zero (+0.26 to +0.43).
- **(b) Lowest FP rate: FAIL** ✗ — KICS FP rate (0.000) is significantly lower than Aegis (0.314); CI for (KICS−Aegis) is [−0.389, −0.236], entirely negative. Aegis beats Checkov and Trivy on FP rate, but not KICS.
- **(c) Fastest (2× threshold): PASS** ✓ — Aegis is 234–752× faster than all competitors.

## 6. Pulumi-specific acceptance

| Check | Result |
|---|---|
| Both layouts covered (10 `template:`-nested + 10 top-level) | ✓ YES |
| Layout diagnostics disclose `template:`-nested usage | ✓ YES (all 10 template-layout projects) |
| Vulnerable Pulumi fixtures → expected rules fire | ⚠ PARTIAL — S3 public, storage public, SG-open (AWS), IMDS fire; **NSG nested `properties.securityRules` NOT normalized** (0 findings on 5 Pulumi NSG fixtures); **Key Vault purge protection NOT detected** on Pulumi (nested `properties:` not flattened, 4 fixtures) |
| Secure Pulumi fixtures → no critical/high findings | ⚠ NOT MET AS STATED — Aegis fires high-severity hardening findings (S3 SSE, PAB, TLS enforcement, KV firewall, storage public-network) on minimal secure fixtures. These are factually correct (the fixtures genuinely lack these controls), not false alarms; the criterion's letter requires zero crit/high, which Aegis's severity scale (hardening=high) cannot satisfy on minimal fixtures. |

**Pulumi adapter gaps** (genuine coverage limitations, disclosed):
1. Azure-native NSG `securityRules` nested inside `properties:` are not normalized → SSH-open NSG rules undetected on Pulumi (5 GT concepts missed: r3101, r3106, r3117, r3119, r3120).
2. Key Vault `enablePurgeProtection` nested in `properties:` not read → purge-protection gap on Pulumi (4 GT concepts missed: r3107, r3112, r3115, r3120).

## 7. Limitations

1. **Single-agent labeling:** Both GT passes performed by the same agent (sequentially, blind). Procedural independence, not personal independence.
2. **Corpus warts:** Duplicate resource names in merged projects; single-file formats only wrote first block (documented in §1).
3. **Classifier tuning:** 10 finding-title mappings added after seeing Aegis results but before final scoring (documented in `labels/CLASSIFIER_CHANGELOG.md`). No new classes; no threshold changes. A/B agreement preserved.
4. **KICS timing:** Single runs (not 5×) on the 30-project subset — documented deviation, same as round 2.
5. **KICS FP CI:** [0.000, 0.000] reflects zero FP events in the 400-sample; the qualitative conclusion (KICS FP << Aegis FP) is robust.
6. **Native skips:** Checkov (Pulumi, compose), Trivy (Pulumi, compose, Bicep) cannot detect concepts in those formats — a real coverage limitation reflected in their recall.
7. **Aegis real detection gaps** (32 FNs, all honest): 6× k8s-no-security-context (no rule), 5× Pulumi NSG (adapter), 4× CFN S3 BucketPolicy public (coverage), 4× Pulumi KV purge (adapter), 5× docker build-tools (no rule), 3× CFN Lambda URL public (coverage), 3× k8s secret-env (no rule), 2× weak DB password (no rule).

## 8. Reproducible commands

```bash
export PATH=~/workspace/toolchain/go/bin:$PATH
cd ~/workspace/aegis-engine
go build -o /tmp/aegis-r3 ./cmd/aegis/   # frozen binary (restore compliance.go from HEAD if build breaks)
cd docs/audit/raw/final-eval-r3
python3 score.py                          # auto-score
python3 adjudicate_aegis.py && python3 adjudicate_checkov.py
python3 adjudicate_trivy.py && python3 adjudicate_kics.py
python3 stats.py                          # bootstrap + decision
```

## Verdict: NOT YET

Aegis achieves the **highest F1** (0.733 vs 0.477/0.318/0.301) and is **by far the fastest** (234–752×), but **KICS has a decisively lower FP rate** (0.000 vs 0.314, CI entirely negative). The three-part win condition requires all three; criterion (b) fails.

**What would change the verdict:** Eliminating Aegis's 54 FPs — particularly the 15 by-design egress findings, 24 public-bucket SSE/PAB findings, 8 build-stage root findings, and 7 gcr.io misclassifications — without reducing TPs. The Pulumi NSG/Key Vault adapter gaps (9 FNs) also merit fixes but do not affect the FP criterion.
