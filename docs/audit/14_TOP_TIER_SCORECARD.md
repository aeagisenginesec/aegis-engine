# Top-Tier Validation Scorecard (Items 1–6)

**Mission:** Top-tier validation tracker — release-decision evidence
**Date:** 2026-10-13
**Branch:** `mission/top-tier-validation` (candidate `2fbe955` + validation
work; 1,151 rules)
**Rule:** No universal-superiority claim is made anywhere in this
package. Each area is judged on the evidence its item produced.

## 6-item checklist

| # | Item | Report | Result |
|---|---|---|---|
| 1 | Fresh blind accuracy benchmark | `14_FINAL_EVAL_R4_REPORT.md` (+ `14_EVAL_R4_PROTOCOL.md`) | **NOT YET** — win condition not met (FP-rate tie with KICS) |
| 2 | Pulumi coverage + cross-format parity | `14_PARITY_MATRIX.md` | **PASS with documented limits** — Pulumi fix holds; parity for tested controls only, not universal |
| 3 | Rule effectiveness audit | `14_RULE_EFFECTIVENESS.md` | **PASS (gate) / PARTIAL (full registry)** — 360/360 Critical/High; 958/1,151 probe-executed |
| 4 | Real CI/CD integration | `14_CI_CD_VALIDATION.md` | **PARTIAL** — workflows built + faithfully simulated; hosted steps blocked on repo creation |
| 5 | Remediation safety + API security | `14_REMEDIATION_API_SECURITY.md` | **PASS (fix safety) / FAIL (API parity)** — 1 High defect (DEFECT-1) |
| 6 | Performance, scale, reliability | `14_SCALE_RELIABILITY.md` + `14_SCALE_RELIABILITY_ADDENDUM.md` | **PASS with fixes** — 10+ bugs found and fixed; fuzzing per-parser |

## 10-area scorecard

### 1. Accuracy — PARTIALLY VERIFIED

- **Evidence:** R4 fresh blind eval, 210 NEW projects (zero file overlap
  with R2/R3, verified by hash), pre-registered protocol + win
  condition, independent adjudication.
- **Numbers:** Aegis F1 **0.921 [0.880, 0.955]**, precision 1.000,
  recall 0.853, FN rate 0.147. Checkov 0.331, KICS 0.371,
  Trivy 0.279.
- **Why not verified:** the pre-registered win condition requires ALL
  THREE (highest F1 + lowest FP rate + fastest). Aegis passes F1 and
  speed decisively but ties KICS on FP rate (see §2). The fixes
  generalize (R3 rescore 1.000 → R4 fresh 0.921; the ~8-point gap is
  the tuning premium), but the superiority claim is **NOT YET**
  established.

### 2. False positives — PARTIALLY VERIFIED

- **Evidence:** R4 adjudicated FP rate **0.000 [0.000, 0.000]** (116 TP,
  0 FP). Per-format breakdowns in the R4 report.
- **Why not verified:** KICS also scores 0.000 — a genuine tie, not a
  win — while finding 3.7× fewer true positives (31 vs 116). The
  three-part win condition fails on this criterion. FP behaviour is
  measured and excellent; the *claim* of "lowest" is not earned.

### 3. Coverage — PARTIALLY VERIFIED

- **Evidence:** Item 2 — the Pulumi fix holds on all 15 round-2
  projects (no zero-finding regression); parity matrix for tested
  controls across TF/CFN/ARM/Bicep/Pulumi/Dockerfile/Compose/K8s;
  supported-types matrix + known limitations published.
- **Why not verified:** parity is proven for tested controls only —
  explicitly NOT universal. Known gaps: Pulumi **TypeScript/JavaScript**
  programs are not parsed (0 findings on TS fixtures in the parent
  session's 20-project scan; YAML/JSON layouts only); `.tf.json`
  is skipped without analysis even under `--strict`; `*.tfvars`
  has no adapter; module `count`/`for_each` not modelled.

### 4. Rule quality — PARTIALLY VERIFIED

- **Evidence:** Item 3 — Quality gate (Critical/High pos+neg):
  **360/360 (100%)**, verified by black-box probe execution (295)
  + existing tests (65). Full registry probe-executed pos+neg:
  **958/1,151 (83.2%)**. Union (probe + existing + new tests):
  1,151/1,151. Rules with no applicable tests: **0**.
- **Why not verified:** the union figure rests in part on a
  heuristic attribution of existing tests (not exhaustively
  hand-verified for medium/low). The independently measured floor
  is the 958/1,151 probe figure. Do NOT quote "1,151/1,151" as an
  execution proof.

### 5. Performance — VERIFIED (on tested workloads)

- **Evidence:** Item 6 — p50/p95/p99, CPU, peak RSS on small/medium/
  large mixed-provider corpora; R4 speed: fastest by 44–176×
  (median per-project scan).
- **Scope note:** measurements describe the tested corpora and
  machine (2 vCPU sandbox). Cold/warm behaviour and caching are
  disclosed in the Item 6 report. Not a claim about all hardware.

### 6. Remediation — PARTIALLY VERIFIED

- **Evidence:** Item 5 — `aegis fix` is **safe**: 0 corruptions,
  0 new findings from applied patches, 0 unrelated findings lost,
  idempotent, comments/formatting preserved, reference values not
  rewritten, `--force` is a no-op (no IAM fixers), malformed files
  untouched.
- **Why not verified:** coverage is **narrow by design — 8 of
  1,151 rules** (Terraform AWS only: 001, 002, 007–012). The
  validation gate conservatively refuses patches whose post-patch
  scan shows "new" findings, including suppression-lift reveals
  (documented limitation). Auto-remediation claims must state the
  8-rule scope.

### 7. Parser safety — PARTIALLY VERIFIED

- **Evidence:** Item 6 — per-parser fuzzing (every parser covered),
  coverage + crash tracking, minimized reproductions, 10+ bugs
  found and fixed (incl. Bicep crashes, CFN/Pulumi alias cycles,
  ARM memoization, manifests multi-doc, TF lenient recovery).
  `item5_yaml_test.go`: YAML duplicate-key/alias inputs fail fast
  with one bounded diagnostic (OOM-path regression).
- **Why not verified:** fuzzing is bounded (time + corpus); the
  prior 217k-execution campaign's broad product-level claim was
  already rejected by audit and is NOT revived here. Parser safety
  holds for the tested threat model (malformed / adversarial /
  cyclic inputs in the fuzz corpora), not universally.

### 8. CI integration — PARTIALLY VERIFIED

- **Evidence:** Item 4 — new `.github/workflows/aegis.yml`
  (PR gate, SARIF upload in ≤5,000-result chunks, PR comment,
  baseline refresh) + `.gitlab-ci.yml`; gate steps executed
  faithfully from literal workflow text; exit codes 0/1/2 verified;
  SARIF structure validated.
- **Why not verified:** hosted steps are **blocked on repo
  creation** (no GitHub repo exists): SARIF upload to code
  scanning, PR-comment API, baseline-refresh PR, GitLab MR notes.
  Known scanner behaviours the workflows work around: `.tf.json`
  skipped silently, `--max-file-size` does not raise the 10 MiB
  cap, SARIF carries no completeness data, `--color` does not
  exist in this build.

### 9. API security — PARTIALLY VERIFIED

- **Evidence:** Item 5 — 23 live probes: auth (401, constant-time
  compare), method checks (405), strict JSON, 413 at 33 MiB,
  1000-file cap, 503 fail-fast at 16 concurrent, path traversal
  safe (in-memory only), secret redaction, token never logged,
  non-loopback no-token warning. No bypass, no crash, no leak.
- **Why not verified:** **DEFECT-1 (High)** — API silently loses
  findings on content-sniffed formats: CFN 11/14 (secret rules
  339/710/850 missing, no warning), ARM 0/35 (cryptic manifests
  warning only). Root cause: `Handles()` sniffs file content from
  disk, which fails for in-memory API files. The API must not be
  presented as CLI-equivalent until fixed.

### 10. Compatibility — PARTIALLY VERIFIED (prior evidence, not re-tested)

- **Evidence (prior, not this round):** post-audit remediation
  (`8b98b87`) added unknown/deprecated rule-ID diagnostics for
  baselines + inline suppressions; `docs/audit/DEPRECATED_RULE_IDS.md`
  maps 39 removed IDs → canonical; baseline-refresh automation in
  the Item 4 workflows; Item 5 notes surviving findings keep
  (RuleID, Resource, Attribute) fingerprints, while stale baseline
  entries matching removed spurious findings stop matching.
- **Why not verified:** this validation round did not re-run a
  dedicated migration-compatibility suite (old-baseline → new
  binary). The prior evidence stands; re-verification is owed
  before a major release.

## Bottom line

**Aegis is not yet releasable as "top tier" on the predeclared
terms** — the win condition fails on the FP-rate tie, the API has a
High coverage defect, and four areas are partial for stated reasons.
But the evidence is strong and honest: best F1 by a wide margin on
fresh blind data (0.921 vs next 0.371), zero false positives,
fastest by 44–176×, 360/360 Critical/High gate, safe (if narrow)
auto-fix, and a hardened API whose one High defect is precisely
diagnosed with a recommended fix.

**To close the gap:** (1) fix DEFECT-1 (API content-aware format
detection); (2) re-run the win condition — the FP tie breaks only
if a future eval separates Aegis from KICS on FP rate, or the
criterion is revised to weight recall (KICS's 0.228 recall vs
Aegis's 0.853); (3) create the GitHub repo to unblock hosted CI
validation; (4) re-verify compatibility on a migration suite.
