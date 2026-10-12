# 02 — Rule Inventory Audit (Phase 3)

**Mission:** Aegis Independent Competitive Validation and Benchmarking Mission
**Date:** 2026-10-12
**Phase:** 3 of 10 — Rule Inventory Audit
**Constraint honored:** read-only on source code. No rules, adapters, engine, or tests were modified. Nothing committed. No branch switch. (Working tree: only the pre-existing tracked `aegis` binary rebuild artifact, untouched.)

## 1. Methodology

**Live-registry enumeration (not grep).** A throwaway Go program (`/tmp/p3dump/main.go`, module `aegis/p3dump` with a `replace` directive to the repo — kept outside the repo; internal-package visibility requires the importing module path to sit under `aegis/`) imports `aegis/internal/rules` plus all ten pack packages and dumps `rules.DefaultRegistry().All()`:
- ID, Title, Description, Severity from the `ir.Rule` interface;
- pack attribution by matching each registered ID against each pack's `Rules()` list (also detects duplicate registration: **0** duplicates across packs; offered-by-packs == registered == **1,185**);
- resource types by probing `AppliesTo` live against the 204-IR-type universe parsed from the adapter typemaps (same method as `benchmark/parity/cmd/matrix`; terraform/planjson are wildcard adapters, so every rule is applicable to them — documented over-approximation, matching the committed matrix);
- compliance via `rules.ComplianceFor`, remediation via `rules.RemediationFor`.

Output: `docs/audit/raw/phase3/registry_dump.json` (1,185 entries). Binary used for scans: `/tmp/aegis-p3` built from HEAD `0c28621` (`go build -o /tmp/aegis-p3 ./cmd/aegis/`); the repo's tracked `aegis` binary was never overwritten.

**Test attribution (static, then manually verified).** For every `_test.go` under `internal/rules/` and `cmd/`, test functions were extracted with brace-counting that strips backtick/double-quoted/char literals (naive counting misattributes after `{` inside strings — found and fixed during the audit). Each test was attributed to rules via, in strength order: instantiated rule types (pack-scoped `type→ID` map: 1,180 types; 5 factory-built K8S rules mapped separately), `RuleID` assertions, `mustFinding(t,…,"ID")` / `mustFire(t,…,"ID",N)` helpers, quoted ID literals, and preceding comments. Pos/neg classification from assertion helpers (`mustFinding`/`expectFinding(N>0)`/`len(f)!=1`/`want 1` → positive; `mustQuiet`/`expectFinding(N=0)`/`len(f)!=0`/`want 0` → negative; single tests asserting both → both), cross-checked against test names (`*Fires*`/`*Quiet*`/`*Positive*`/`*Negative*`). Ambiguous and one-sided cases for critical/high rules were **manually inspected and adjudicated** (details §6). `go test -count=1 ./internal/rules/...` re-run independently: **12/12 packages pass** (GOTMPDIR redirected to home disk; /tmp is a full 512M tmpfs).

**Fixture verification.** Minimal positive fixtures (violating) and negative fixtures (fixed) were built per rule and scanned end-to-end with `/tmp/aegis-p3 scan` (JSON output, per-resource finding check).

## 2. Registry reconciliation: 1,185 (runtime) vs 1,193 (baseline grep)

**Resolved.** The true numbers:

| Source | Count | Explanation |
|---|---|---|
| Live registry (`aegis doctor`, dump program) | **1,185** | one entry per registered rule; `Registry.Register` dedupes silently but 0 duplicates were offered |
| Unique IDs in non-test source (this audit's grep) | 1,190 | 1,185 registered + **5 comment-only IDs** |
| Baseline's `raw_baseline_rule_ids.txt` | 1,193 | 1,190 + **3 test-file-only IDs** (their grep's test exclusion leaked) |

The 5 source-but-unregistered IDs (`docs/audit/raw/phase3/reconciliation.json`):
- `AEGIS-AWS-545` — `internal/rules/aws/finalgaps2.go:17`: comment `// AEGIS-AWS-545: RDS instance without Multi-AZ` — a **planned but never implemented** rule. Dead reference.
- `AEGIS-AWS-606`, `AEGIS-AWS-619`, `AEGIS-AWS-627`, `AEGIS-AWS-628` — `internal/rules/aws/hygiene.go:5-15`: comments documenting IDs **deliberately never created** because they'd duplicate existing rules (606→`AEGIS-AWS-310` EC2 detailed monitoring; 619→`AEGIS-AWS-306` EKS control-plane logging; 627→`AEGIS-AWS-209` VPC flow logs; 628→`AEGIS-AWS-445` S3 access logging). Intentional dedup notes, not rules.

The 3 baseline-only IDs (all in `*_test.go`, wrongly counted as non-test):
- `AEGIS-AWS-999` — placeholder ID used in `compliance_test.go`, `suppress_test.go`, `remediation_test.go`, `engine_test.go`, `cmd/aegis/fix_test.go` (means "nonexistent rule").
- `AEGIS-COMPOSE-00` — string-concatenation artifact in `compose_test.go:111` (`"AEGIS-COMPOSE-00" + string(rune('1'+i))`).
- `AEGIS-AWS-558` — `engine_test.go:120` comment: "4 AWS rules removed by the concurrent Phase-4 refactor (incl. AEGIS-AWS-558)" — a removed rule.

**No registered rule lacks a source definition. No ID is defined by two types. No rule type with an `ID()` method is dead** (1,195 struct types scanned; 3 never instantiated, all non-rule helpers — `docs/audit/raw/phase3/dead_types.json`). Two Go type names are reused across packs (`sgOpenIngress`: alibaba `AEGIS-ALI-009` vs aws `AEGIS-AWS-004`; `kmsNoRotation`: gcp `AEGIS-GCP-012` vs aws `AEGIS-AWS-335`) — legal (separate packages), mildly confusing, not a defect. Five K8S rules are factory-built (`hostNamespaceRule`, `&noProbe{}`) rather than one-type-per-rule; all registered and located (`id_location.json`).

Severity split (registry): **critical 35, high 328, medium 503, low 319** — critical+high = 363, matching the quality gate's denominator.

## 3. Per-pack inventory

| pack | rules | crit | high | med | low | pos&neg | pos-only | no pos/neg test | compliance-mapped | detailed remediation |
|---|---|---|---|---|---|---|---|---|---|---|
| alibaba | 12 | 3 | 5 | 4 | 0 | 12 | 0 | 0 | 0 | 0 |
| aws | 482 | 9 | 151 | 187 | 135 | 479 | 3 | 0 | 218 | 39 |
| azure | 313 | 0 | 84 | 154 | 75 | 257 | 19 | 37 | 0 | 8 |
| compose | 8 | 0 | 5 | 3 | 0 | 8 | 0 | 0 | 0 | 0 |
| docker | 35 | 0 | 6 | 6 | 23 | 35 | 0 | 0 | 0 | 0 |
| gcp | 285 | 19 | 55 | 130 | 81 | 227 | 58 | 0 | 25 | 9 |
| k8s | 25 | 2 | 11 | 9 | 3 | 25 | 0 | 0 | 0 | 1 |
| oci | 8 | 2 | 4 | 2 | 0 | 8 | 0 | 0 | 0 | 0 |
| supplychain | 9 | 0 | 4 | 4 | 1 | 9 | 0 | 0 | 0 | 0 |
| terraform | 8 | 0 | 3 | 4 | 1 | 8 | 0 | 0 | 0 | 0 |
| **total** | **1,185** | **35** | **328** | **503** | **319** | **1,068** | **80** | **37** | **243** | **57** |

Notes:
- Pack split differs slightly from the baseline's grep split (AWS 489→482, AZURE 308+AZR 5→313) because the baseline counted the 5 comment-only and 3 test-only IDs.
- "no pos/neg test" (37) = 2 high with **no detection test at all** (§4) + 35 rules whose only tests are property/meta tests (determinism, ID-order, registry-count, evidence-leak checks) — exercised, but never asserted to fire or stay quiet.
- Compliance: 243/1,185 mapped (NIST-800-53: 271 refs, PCI-DSS-4.0: 85, CIS-AWS-1.5: 41; all AWS/GCP rules — azure/alibaba/docker/k8s/oci/compose/supplychain/terraform packs have **zero** compliance mappings).
- Remediation: 57/1,185 have detailed entries in `remediationDB`; the rest get category-aware fallback templates. The `remediation.go` header claims "detailed entries for all Critical rules" — **false**: 16 of 35 critical rules (e.g. `AEGIS-ALI-002`, `AEGIS-ALI-007`, `AEGIS-ALI-009`, `AEGIS-GCP-038`, `AEGIS-GCP-040`, `AEGIS-GCP-051`, `AEGIS-GCP-068`, `AEGIS-GCP-072`) have no detailed entry and fall back to templates. Fallback quality is reasonable (category-aware: encryption/public-exposure/credential/network templates with doc links), but the header comment overstates coverage.
- Support matrix (`benchmark/parity/support-matrix.json`, rule_count 1,185) covers exactly the registry ID set (0 missing, 0 extra — verified). Adapter-count distribution: 259 rules on 2 adapters, 355 on 3, 352 on 4, 218 on 5, 1 on 9. (terraform/planjson are wildcard adapters: every rule is statically applicable.)

Machine-readable inventory: `docs/audit/raw/phase3/rule_inventory.csv` — one row per rule: `id,pack,severity,file,test_present,test_positive,test_negative,test_files,adapters,compliance,remediation`.

## 4. Findings

### F1 — 46 duplicate rule pairs (77 distinct rules), 19 with conflicting severities — HIGH
Identical titles (token-set Jaccard 1.0) within a pack, verified by reading `AppliesTo`+`Check` and by live scan. Pattern: early rules duplicated by the later maximal-expansion wave (e.g. azure `azure13.go` vs `azure21.go`, gcp `gcp3.go` vs `gcp4.go`, aws hygiene vs deep files). Examples, live-verified to **double-fire on the same resource**:
- `AEGIS-AZURE-155` (medium) vs `AEGIS-AZURE-298` (high) — "Data Factory with public network access enabled": both fired on `azurerm_data_factory.open` (`fixtures/duplicates/scan.out`). Same check, conflicting severity.
- `AEGIS-GCP-058` vs `AEGIS-GCP-119` (both medium) — "Compute instance with serial port access enabled": both fired on `google_compute_instance.serial`; Check bodies functionally identical.
- Full list in `docs/audit/raw/phase3/duplicate_candidates.json` (46 unique pairs; 19 severity mismatches, e.g. `AZURE-146`(low)/`AZURE-203`(medium), `AZURE-032`(low)/`AZURE-144`(medium), `AWS-625`(low)/`AWS-752`(medium), `AWS-440`(medium)/`AWS-719`(high), `GCP-011`(high)/`GCP-112`(medium)). The 5 intentionally-skipped duplicates documented in `hygiene.go` comments (606/619/627/628) show the authors knew about this hazard; the 46 pairs slipped through anyway. Effect: duplicate findings per scan, inflated rule count, and contradictory severity for the same issue.

### F2 — 2 high-severity rules with zero detection tests — MEDIUM
`AEGIS-AZURE-049` (MSSQL database without TDE) and `AEGIS-AZURE-098` (MariaDB without SSL enforcement): the only test mentioning them is `TestRulesInIDOrder` (a registry-ordering meta test). The quality gate counts them as "tested" (mention-based). Both rules **do work** — verified with live fixtures (`fixtures/suspicious/meta_only.tf`: fired on explicit `false`, quiet on `true`) — but a future regression in either would be caught by nothing. (Note: both only fire on explicit `false`; absent attribute → no finding, a conservative choice worth documenting.)

### F3 — quality-gate "363/363 tested" overstates what is verified — MEDIUM
The gate's `rule-coverage` check is string-mention-based (`strings.Contains(testFile, ruleID)`). Independent verification:
- 363/363 critical/high mentioned in some test file — **reproduced** (`[PASS] rule-coverage metric=363/363`, re-run 2026-10-12).
- But by detection-test evidence: **334/363** have positive+negative tests (27 crit + 307 high); **27** have positive-only tests (8 crit + 19 high, listed in `pos_only_crit_high.json`); **2** have no detection test (F2).
- Positive-only criticals: `AEGIS-GCP-038/040/051/068/077/082/096`, `AEGIS-K8S-001`(neg via shared full-registry quiet test — counted as both after manual verification). Positive-only highs include `AEGIS-AWS-556`, `AEGIS-AWS-629` (its `TestKillChain629NoExposure` **asserts nothing** — the computed `hasConcreteEntry` is discarded with `_ =`; degenerate test), `AEGIS-AZURE-039/048/054/055/084/097`, 19 GCP rules (single `*Fires` tests, e.g. `TestGCP038_PublicFires` with no quiet counterpart).
- Mitigating: `TestUnknownNeverFires_Check` (aws pack) asserts no low+-severity finding on all-unknown attributes for every AWS rule — a weak shared negative. No equivalent exists for azure/gcp packs.

### F4 — remediation coverage header overstates reality — LOW
`remediation.go` claims detailed entries "for all Critical rules and the highest-impact High rules"; actual: 57 detailed entries, 16/35 criticals and 304/328 highs fall back to templates (§3).

### F5 — dead comment reference `AEGIS-AWS-545` — LOW
`finalgaps2.go:17` references a planned-but-never-implemented rule ("RDS instance without Multi-AZ"). No rule, no test, no registration — a dangling ID that will confuse future audits.

### Non-findings (checked, clean)
- No duplicate ID registration; `Register`'s silent-dedupe never triggers.
- No dead rule types; every `ID()` has exactly one definition site.
- `aegis doctor` count, dump-program count, pack-offered count, and support-matrix count all agree at 1,185.
- All 1,185 rules have at least one attributed test of some kind (detection, property, or meta).

## 5. Test-coverage numbers (exact)

Definitions: `test_present` = ID string appears in any `_test.go` (the gate's definition); `test_positive`/`test_negative` = an attributed test asserting the rule fires / stays quiet (unit/IR level), including verified shared negatives.

| severity | total | pos&neg | pos-only | neg-only | neither pos nor neg | no test mention |
|---|---|---|---|---|---|---|
| critical | 35 | 27 | 8 | 0 | 0 | 0 |
| high | 328 | 307 | 19 | 0 | 2 | 0 |
| medium | 503 | 455 | 38 | 0 | 10 | 40 |
| low | 319 | 279 | 15 | 0 | 25 | 0 |
| **total** | **1,185** | **1,068** | **80** | **0** | **37** | **41** |

So: **1,068/1,185 with positive+negative fixture verification, 80/1,185 positive-only, 37/1,185 with tests that assert neither** (property/meta tests), **40/1,185 with no test-file mention at all** (all medium; none critical/high). No rule is neg-only.

**Critical/high 20-sample assertion-quality inspection** (seed 20261012, stratified 4 critical + 16 high; IDs in `sample20_crit_high.json`): 18/20 have pos+neg; 2 pos-only (`AEGIS-GCP-061`, `AEGIS-GCP-086` — single `*Fires` tests, verified no quiet counterpart exists). Assertion quality of the inspected tests is **good**: `mustFinding` asserts exactly-1 finding + correct rule ID + non-empty resource + evidence attribute; `mustQuiet` asserts 0 findings; severity explicitly asserted in most (e.g. `TestGCP136` checks high, `TestPrivilegedFires` checks critical, `TestVulnerableVersionFires` checks high + resource address + evidence attribute). Negative tests routinely cover the fixed, absent, and unknown-value cases. Weak spots found: `TestKillChain629NoExposure` asserts nothing (F3); `TestRulesInIDOrder`-style meta tests count toward the gate without testing detection.

**Medium/low random sample: 60/60 live fixture PASS.** Method: `random.sample` over the 822 medium/low rules, `random.seed(20261012)` (IDs in `sample60_med_low.json`; pack mix 24 aws / 14 azure / 14 gcp / 6 docker / 1 k8s / 1 alibaba; 39 medium + 21 low). For each rule I read its `Check` source, wrote a minimal violating Terraform/Dockerfile/K8s fixture (`fixtures/sample60/pos/`) and a fixed counterpart (`fixtures/sample60/neg/`), scanned both with `/tmp/aegis-p3 scan --format=json`, and checked the finding per resource address. Result: **60/60 fired on the positive fixture and stayed quiet on the negative fixture** (`sample60_results.json`, raw scans `scan_positive.json`/`scan_negative.json`). Two fixture bugs found and fixed during the run (GCP-062: rule fires on absent/empty/default-substring SA email, not on the real default-SA email pattern — a documented detection limitation; AWS-570: cross-resource rule reports on the bucket, and needs name-string linkage like its unit test, not TF references). No rule failed to fire on an obvious fixture; no rule fired on its secure fixture.

## 6. What was manually verified vs heuristic

Static attribution is a lower bound; these were verified by reading the tests: `AEGIS-AWS-103` (negative via `TestRDSPath_Negative` → helper `findRDSPaths`), `AEGIS-K8S-001/002` (negative via full-registry `TestCompliantContainerQuiet`/`TestNoSecurityContextQuiet`), `AEGIS-K8S-007/008/009` (`TestK8S007_009` does `mustFire(id,1)` + `mustFire(id,0)` per ID), `AEGIS-SC-001` (negative via adjacent `TestFixedVersionSilent`), `AEGIS-AWS-629/630` (positive tests verified; 629's negative test is degenerate). The 46 duplicate pairs: titles identical (Jaccard 1.0); logic equivalence verified by reading `AppliesTo`+`Check` for a sample and by live double-fire for 2 pairs; the remaining 44 pairs were **not** individually logic-diffed — flagged as candidates with evidence, not proven duplicates.

## 7. Limitations / not verified

- "Neither pos nor neg" medium/low rules (35) were not individually inspected; many are covered by property tests (determinism, evidence-leak, unknown-quiet).
- Duplicate-pair logic equivalence proven for 2 pairs live + sampled code reads; the other 44 rest on identical titles + overlapping resource types.
- Fixture polarity for `absent`-fires rules: negative fixtures used the documented fixed configuration; provider-default semantics were taken from the rule's own comments/tests.
- The `resource_types` column in the dump/CSV reflects the 7 non-wildcard adapters' typemaps; terraform/planjson accept every rule (wildcard over-approximation, same as the committed matrix).
- Sibling phase reports (03, 05, 06, 07, 08) appeared in `docs/audit/` during this run — not read, not touched.

## 8. Raw artifacts

- `docs/audit/raw/phase3/registry_dump.json` — live-registry dump (1,185 rules: id, pack, severity, title, description, resource types, adapters, compliance, remediation text+refs)
- `docs/audit/raw/phase3/rule_inventory.csv` — one row per rule: `id,pack,severity,file,test_present,test_positive,test_negative,test_files,adapters,compliance,remediation`
- `docs/audit/raw/phase3/reconciliation.json` — 1185-vs-1193-vs-1190 breakdown (5 comment-only + 3 test-only IDs)
- `docs/audit/raw/phase3/id_location.json` — implementation file+line per rule ID (1,185/1,185)
- `docs/audit/raw/phase3/id_testfiles.json`, `ids_no_test_mention.json` — mention-based coverage (gate's definition)
- `docs/audit/raw/phase3/test_attribution.json` — per-rule attributed tests with pos/neg/both/other/meta classification + strength
- `docs/audit/raw/phase3/pos_only_crit_high.json` — the 27 positive-only critical/high rules
- `docs/audit/raw/phase3/duplicate_candidates.json` — 233 similar-title pairs (46 identical)
- `docs/audit/raw/phase3/pack_type2id.json`, `type2id.json`, `dead_types.json` — static-analysis intermediates
- `docs/audit/raw/phase3/remediation_detailed_ids.txt` — 57 IDs with detailed remediation
- `docs/audit/raw/phase3/sample20_crit_high.json` — the 20-sample IDs + seed
- `docs/audit/raw/phase3/sample60_med_low.json`, `sample60_rule_src.txt`, `sample60_resmap.json`, `sample60_results.json` — 60-sample materials
- `docs/audit/raw/phase3/fixtures/sample60/{pos,neg}/` + `scan_positive.json` + `scan_negative.json` — 60-sample fixtures and raw scan outputs
- `docs/audit/raw/phase3/fixtures/suspicious/` — AZURE-049/098 fire/quiet verification
- `docs/audit/raw/phase3/fixtures/duplicates/` — 155/298 + 058/119 double-fire proof
- `docs/audit/raw/phase3/dump_stderr.log` — dump program diagnostics
