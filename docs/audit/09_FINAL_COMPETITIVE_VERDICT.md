# 09 — Final Competitive Verdict

**Mission:** Aegis Independent Competitive Validation and Benchmarking Mission
**Date:** 2026-10-12
**Phase:** 10 of 10 — Final verdict
**Subject:** `~/workspace/aegis-engine`, branch `fix/demo-defects-d1-d3`, HEAD `0c28621`
**Analyst posture:** read-only validation across all phases; no detection logic changed during the mission (D1–D3 fixes predate it and are on this branch, unmerged to main).

---

## 1. What was done (10 phases)

| Phase | Report | Result |
|---|---|---|
| 1. Baseline & evidence freeze | `00_BASELINE_AND_EVIDENCE.md` | Frozen: `0c28621`, 1,185 rules, gate 5/5, 32/32 tests, race-clean |
| 2. Adapter parity verification | `01_ADAPTER_PARITY_REPORT.md` | Prior audit stands on fix branch; parity tests pass |
| 3. Rule inventory audit | `02_RULE_INVENTORY_AUDIT.md` | 1,185 reconciled; coverage 1,068 pos+neg / 80 pos-only / 37 meta / 40 untested; **46 duplicate pairs (HIGH)** |
| 4. Accuracy & ground truth | `03_ACCURACY_AND_GROUND_TRUTH.md` | Recall 0.94–1.00; contamination disclosed; fresh 16-project probe 18/18; **2 new HIGH defects** |
| 5. Competitive benchmark | `04_COMPETITIVE_BENCHMARK_REPORT.md` | 80 runs; Aegis fastest everywhere (6×–296×); KICS leads raw counts on 2 corpora |
| 6. Performance & scale | `05_PERFORMANCE_AND_SCALE_REPORT.md` | Superlinear scaling (exp ≈1.37; engine →1.88); 2 completeness bugs |
| 7. Remediation safety | `06_REMEDIATION_SAFETY_REPORT.md` | 20 cases pass; no corruption/leaks; 1 automation-hazard defect |
| 8. Self-security | `07_SELF_SECURITY_AUDIT.md` | API clean; 1 fuzzer-found parser panic (contained); 20/20 adversarial handled |
| 9. CI integration | `08_CI_INTEGRATION_REPORT.md` | SARIF schema-valid; exit codes 8/8; pipelines simulated (no Docker daemon) |
| 10. Final verdict | this document | below |

---

## 2. Claim classification

Every major Aegis claim, classified against mission evidence.

### VERIFIED

| Claim | Evidence |
|---|---|
| **1,185 executable rules** | Live-registry dump (`DefaultRegistry().All()`), `aegis doctor`, pack-offered count, and support-matrix count all agree at 1,185. 0 duplicate registrations. (Phase 3) |
| **Speed leadership on tested corpora** | 80 runs, pinned versions, 5-run medians: Aegis fastest on all 4 corpora, 6×–296× vs nearest competitor (Trivy). Zero crashes/timeouts. (Phase 5) |
| **Deterministic output** | Byte-identical SHA-256 across 3× runs in Phases 4, 6, 8, 9 (incl. 500-file repo, 5.68 MB output). (Phases 4/6/8/9) |
| **Quality gate 5/5 PASS** | Re-run on frozen commit: precision 100.0% (tp=355), recall 100.0%, 363/363 mention-tested, p95 25.6 ms, parser-safety 15/15. (Phase 1) |
| **Full test suite green + race-clean** | `go test -count=1 ./...`: 32/32 packages pass; `-race` on cmd/rules/adapters: clean. (Phase 1) |
| **SARIF 2.1.0 validity** | Validated against the official schema + GitHub structural rules; 421-result consumer run PASS. (Phase 9) |
| **Exit-code contract** | 8/8 cases match docs (0/1/2). (Phase 9) |
| **Baseline/fingerprint stability** | New-only surfacing works; expiry/removal behave; fingerprints byte-stable. (Phase 9) |
| **HTTP API loopback default** | Verified via `ss`: binds 127.0.0.1:8734 only; no pprof; 413 on oversized; no leaks under slow-loris; no stack-trace leaks. (Phase 8) |
| **Remediation causes no corruption** | 20 cases: patches valid/minimal, rescan clean, zero new findings, secrets never leaked, symlinks not followed, IAM/networking refused without `--force`. (Phase 7) |
| **Recall on tested material** | 18/18 fresh probe, 119/120 corpus-v2 dev, 40/40 held-out, 32/34 demo scenarios (2 uncertainty-visible, 0 silent). Critical/high recall 64/65 dev, 21/21 held-out, 16/16 probe. 0 severity mismatches on 177 matched findings. (Phase 4) |
| **Single static binary, zero runtime deps** | `go build` produces one binary; doctor confirms. (Phase 1) |

### PARTIALLY VERIFIED

| Claim | What holds | What doesn't |
|---|---|---|
| **"363/363 critical/high tested"** | All 363 IDs appear in test files (gate reproduced). | True positive+negative coverage is **334/363**; 27 positive-only; **2 high rules (AZURE-049/098) have zero detection tests**. The gate is mention-based. (Phase 3) |
| **Accuracy leadership vs competitors** | Aegis recall 0.94–1.00 on tested material; adjudicated probe precision 0.990. | Corpora are Aegis-centric/contaminated; **no competitor was scored on shared labels** — "outperforms on accuracy" vs Checkov/KICS/Trivy is **not established**. (Phase 4) |
| **"FP rate 0.000"** | 0/42 demo secure tested-conditions; 0/60 corpus-v2 secure projects; 0.0 false-alarm rate on comprehensive secure projects. | 1 genuine FP found on fresh material (AZURE-187, P4-DEF-01); minimal fixtures show hygiene noise; strict precision depressed by label incompleteness. (Phase 4) |
| **Adapter semantic parity** | 331/331 parity subtests on 148 fixtures; determinism + race green. | P4-DEF-01 (ARM nested-casing boundary) and P4-DEF-02 (for_each whole-file skip) are parity-class defects found *after* the audit; Bicep `for`/`module` skipped; `.tf.json` unsupported. Coverage = 148 tested cases, not universal. (Phases 2/4) |
| **Scan-completeness contract** | Per-file discovered/parsed/skipped/failed accounting works; `--strict` exits 2 naming the file. | Over-cap files **silently undiscovered** (no diagnostic despite `--help` promising one); size-excluded files leave no skip record; `for_each` warning flips a file to skipped while **dropping its resources**. (Phases 6/8) |
| **Remediation safety** | 20/20 cases safe (see VERIFIED). | **Bulk-apply silent no-op loop** on duplicate resource addresses (automation hazard, medium-low); JSON output has a trailing plaintext line breaking strict parsers (low). (Phase 7) |
| **Self-security** | API clean; 20/20 adversarial inputs handled; 9/10 fuzz targets clean (~2M execs). | **1 fuzzer-found Bicep parser panic** (contained by safeParse, medium); quality-gate "parser-safety 15/15" covers **only the Terraform adapter**; `0.0.0.0` bind gives no warning. (Phase 8) |
| **CI-ready** | SARIF valid; exit codes; baselines; repeatability all demonstrated. | Pipelines were **simulated** (no Docker daemon for live `act`); shipped examples lack `--strict`; GitLab docs example used wrong schema; self-scan SARIF exceeds GitHub's 5,000-result cap. (Phase 9) |
| **Attack paths / kill chains** | Feature exists; 363-rule regression coverage includes attack-path tests. | Exploitability not validated; paths are illustrative configuration relationships (unchanged from LIMITATIONS.md). Not deeply audited this mission. |
| **1,068/1,185 pos+negative verified** | Exact per-rule attribution + 60/60 live medium/low sample pass. | 80 pos-only, 37 meta-only, 40 untested (all medium); one degenerate test (`TestKillChain629NoExposure` asserts nothing). (Phase 3) |

### UNVERIFIED

| Claim | Why |
|---|---|
| **"15 capabilities no competitor has"** | No feature-by-feature audit of current Checkov/KICS/Trivy versions was performed. Reframe as: "Aegis combines these capabilities in one tested workflow." |
| **"Top-tier / No. 1 IaC scanner"** | No predeclared head-to-head accuracy evaluation on shared independent labels exists. Speed leadership alone does not support it. **Not recommended.** (see §5) |
| **Multi-format accuracy beyond TF** | ARM/Bicep/Pulumi/Docker/Compose/K8s accuracy rests on a 16-project probe + parity fixtures, not labeled corpora. |

### FAILED

| Claim / expectation | Evidence |
|---|---|
| **"No duplicate rules"** (implied by clean 1,185 count) | **46 duplicate rule pairs** (77 distinct rules), 19 with conflicting severities; live double-fire proven. Inflates finding counts and contradicts severity consistency. (Phase 3, F1-HIGH) |
| **Linear scalability** | Measured exponent ≈1.37 end-to-end; rule engine →**1.88 (near-quadratic)** past ~4k resources. The main architectural scalability risk. (Phase 6) |
| **"Parser-safety 15/15" as whole-product claim** | Covers the Terraform adapter only; missed the Bicep panic found by fuzzing. Accurate for what it measures; misleading as a product-level claim. (Phase 8) |

---

## 3. Consolidated defect register

**Fixed before/during mission (on this branch, unmerged to main):**
- D1 (HIGH): IAM AdministratorAccess attachment coverage gap — fixed, regression-tested.
- D2: Lambda KMS attribute false positive — fixed.
- D3: Silent skips on resource references → explicit UNCERTAIN — fixed.
- Parity audit's 7 defects (CFN property mapping, Bicep param defaults, ARM/Pulumi nested encryption, etc.) — fixed.
- Expansion FP wave (655/743/716/772) — fixed.

**Open (found by this mission, not fixed — read-only phases):**

| ID | Severity | Defect | Phase |
|---|---|---|---|
| F1 | **HIGH** | 46 duplicate rule pairs, 19 conflicting severities; double-fire proven | 3 |
| P4-DEF-01 | **HIGH** | AZURE-187 FP on ARM/Bicep Key Vault (`defaultAction` casing boundary) | 4 |
| P4-DEF-02 | **HIGH** | `for_each` unresolvable → whole file skipped, resources dropped, message lies | 4 |
| F-1 | MEDIUM | Bicep parser panic on 15-byte input (contained by safeParse; repro saved) | 8 |
| F2 | MEDIUM | 2 high rules (AZURE-049/098) with zero detection tests | 3 |
| Perf-1 | MEDIUM | Rule-engine scaling →quadratic past ~4k resources | 6 |
| F2 (P7) | MEDIUM-LOW | Bulk `fix --apply` silent no-op loop on duplicate addresses (automation hazard) | 7 |
| F3 | MEDIUM | Quality-gate "tested" is mention-based, overstates verification (334/363 true) | 3 |
| F1 (P7) | LOW | `fix --format=json` appends plaintext line after JSON | 7 |
| F-2/3/4/6 | LOW | Bicep unterminated-string silent accept; over-size files vanish from completeness; no `0.0.0.0` bind warning; TF 10 MiB hard cap vs flag | 8 |
| F4/F5 | LOW | Remediation header overstates critical coverage (57 detailed, not 35/35); dangling AWS-545 comment | 3 |
| P6-C1/C2 | LOW–MED | Over-cap file silently undiscovered; completeness skip-record gaps | 6 |

---

## 4. Competitive position (evidence-backed)

| Dimension | Verdict | Basis |
|---|---|---|
| **Speed** | Aegis leads | 6×–296× faster than nearest competitor on 4 corpora, 80 runs, pinned versions (Phase 5) |
| **Recall on tested material** | Aegis strong (0.94–1.00) | Phases 3–4; competitor recall on shared labels **not measured** |
| **False-positive discipline** | Aegis strong by design | 0.0 false-alarm on 60 comprehensive secure projects; 1 genuine FP found on fresh material (Phase 4) |
| **Raw finding volume** | KICS leads on 2/4 corpora | 1437 vs 957 (vuln-200), 806 vs 441 (corpus-v2) — counts, not accuracy (Phase 5) |
| **Platform breadth** | KICS leads | 17 formats claimed; Aegis covers 9–10 input paths (Phase 1) |
| **Container/image scanning** | Trivy leads | Different category; acknowledged |
| **Determinism / CI ergonomics** | Aegis leads | Byte-identical outputs, SARIF-valid, exit codes, baselines (Phases 7/9) |
| **Accuracy vs competitors** | **Undecided** | Requires shared independent labels — not done (Phase 4 §8 lists requirements) |

**What Aegis can honestly claim today:** the fastest IaC scanner tested, with strong measured recall, explicit uncertainty handling, deterministic output, and a validated remediation workflow — on the tested corpora and scopes.

**What it cannot claim:** overall No. 1, superior accuracy to named competitors, universal multi-format parity, or whole-product parser safety.

---

## 5. Release readiness

**Ready:** internal/beta use, CI piloting with `--strict`, demo and evaluation distribution — with the defect register disclosed.

**Not ready:** a "No. 1 IaC scanner" public claim; production rollout where duplicate severities (F1) or the `for_each` skip (P4-DEF-02) could erode trust.

**Predeclared No. 1 evaluation (not yet run):** Aegis could claim overall leadership only after (a) F1/P4-DEF-01/P4-DEF-02 fixed with regression tests, (b) an externally-labeled, cryptographically held-out corpus scored for Aegis + Checkov + KICS + Trivy on identical labels with a published adjudication protocol, and (c) Aegis winning on predeclared primary metrics (e.g. F1 at medium+ severity, critical/high recall) within the stated scope. Phase 4 §8 specifies the full design.

**Recommended next actions (ordered):**
1. Fix F1 (dedupe 46 pairs — biggest trust risk), P4-DEF-01, P4-DEF-02 with regression tests.
2. Fix F-1 (Bicep panic guard), P7-F2 (bulk-apply no-op), completeness skip records.
3. Extend parser-safety gate to all 9 adapters; make rule-coverage gate assertion-based (pos+neg), not mention-based.
4. Profile the quadratic engine component (bisect rule packs at 4k+ resources, black-box).
5. Commission the independent evaluation per Phase 4 §8; merge the fix branch to main only after (1).
6. Re-run this mission's Phase 5 + 4 protocols post-fix as the predeclared No. 1 evaluation.

---

## 6. Reproducibility

- Commit: `0c28621b8767702c8edc48c7d9a57313ce24be98`, branch `fix/demo-defects-d1-d3` (unmerged).
- Toolchain: go1.25.4 (`~/workspace/toolchain/go`); Checkov 3.3.26; KICS 2.1.20; Trivy 0.75.0; 2 vCPU / 7–8 GB RAM.
- Key commands: `go build -o /tmp/aegis-x ./cmd/aegis/`; `go test -count=1 ./...`; `go test -race ./cmd/aegis/ ./internal/rules/... ./internal/adapter/...`; `./aegis doctor`; `./aegis quality-gate`; `go test ./cmd/aegis/ -run TestParity`; `docs/audit/raw/phase5/rerun.sh`.
- Raw evidence: `docs/audit/raw/` (per-phase), `docs/audit/demo-raw/`, `benchmark/parity/`, `benchmark/showdown_1185_raw.json`.
- Checksums: rule-ID list `docs/audit/raw_baseline_rule_ids.txt` (1,193-line grep superset; registry dump at `docs/audit/raw/phase3/registry_dump.json`, 1,185).

---

## 7. Final execution summary

**Stages completed:** 10/10. **Source modified:** none during mission (read-only). **Commits by mission:** pending (single commit of `docs/audit/` additions).

**Test/verification counts:** full suite 32/32 pass (fresh); race clean; quality gate 5/5; parity 331/331; competitive 80/80 runs ok; remediation 20/20 safe; fuzz ~2.07M execs (1 contained crasher); adversarial 20/20 handled; CI exit codes 8/8; rule inventory 1,185 reconciled; 60/60 medium/low live-sample pass; accuracy probe 18/18 recall.

**Defects fixed (pre-mission, on branch):** D1, D2, D3 + 7 parity defects + 4 expansion FPs.
**Defects found (open):** 3 HIGH (F1 duplicates, P4-DEF-01, P4-DEF-02), 3 MEDIUM, 7 LOW/MED-LOW — see §3.
**Remaining blockers for a No. 1 claim:** independent shared-label evaluation (not run); F1/P4-DEF-01/P4-DEF-02 fixes; fix branch unmerged.
**Next action:** maintainer triage of §3, starting with F1.
