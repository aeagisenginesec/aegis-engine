# 14 — Rule Effectiveness Audit

**Branch:** `mission/top-tier-validation` · **Date:** 2026-10-13 · **Item:** 3 of 6
**Registry measured:** 1,151 rules — critical 35, high 325, medium 481, low 310.
**Full machine-readable table:** [`raw/rule-effectiveness.csv`](raw/rule-effectiveness.csv)
(1,151 rows: rule ID, severity, pos test?, neg test?, boundary tested?, verdict,
probe evidence, unknown behavior, fix note).

## 1. Gate vs. full registry — do NOT conflate these

| Metric | Number | Meaning |
|---|---|---|
| **Quality gate (Critical/High pos+neg)** | **360 / 360 (100%)** | Every Critical/High rule has a verified positive (fires) + negative (quiet) test. Verified by: black-box probe execution for 295 rules + existing tests for the other 65 (8 of them read and confirmed by hand, because the test-attribution heuristic misses `len(...)`-style assertions). |
| **Full registry, probe-executed pos+neg** | **958 / 1,151 (83.2%)** | Independently measured by executing every rule against generated vulnerable/secure inputs (black-box probe, no test-existence counting). Breakdown: critical 28/35, high 267/325, medium 400/481, low 263/310. |
| **Full registry, union (probe + existing + new tests)** | **1,151 / 1,151** | Every rule has pos+neg coverage from at least one of: probe witness + generated replay test (280), probe witness + existing test (654), existing test alone (163), new hand-written test (27), or fix + regression test (27). |
| **Rules with no applicable tests** | **0** | No rule is left without a pos+neg test. |

Notes on the numbers:

- The task brief quoted a gate of "355/355". The live registry on this branch has
  **360** Critical+High rules, and `13_ACCURACY_100_REPORT.md` also reports the gate
  as **360/360**. The 355 figure appears stale; this report uses the live 360.
- The union figure (1,151/1,151) rests in part on a heuristic attribution of
  *existing* tests (test function mentions the rule ID/type and asserts a firing
  and a quiet case). That heuristic **under-counts** (it misses `len(...) == 1` /
  `len(...) == 0` assertions, `mustFire`, and graph-fixture tests — 8 flagged
  Critical/High gaps were all confirmed covered by hand-reading the tests). It was
  not exhaustively manually verified for medium/low rules. The **probe-executed
  958/1,151 is the independently measured floor**; the union is the best
  available total, not an execution proof for the remaining 193 rules.
- The probe itself has known blind spots (Section 5): it missed 178 firing inputs
  that existing tests cover (enum values like `EC2`/`unlimited`, nested-block
  shapes, graph fixtures). A probe "no-pos" is **not** evidence a rule is dead —
  only the 3 rules in Section 4.1 were actually dead.

## 2. Method

1. **Black-box probe** (Go, in scratch — not a deliverable): executed every rule
   against a battery of generated inputs per applicable resource type — empty,
   canonical vulnerable/secure assignments, scalar sweeps, 1- and 2-level block
   nesting, k8s structural shapes, name variants, cross-resource sets — plus an
   all-unknown and all-ref kitchen-sink input per rule. Recorded a firing input
   (pos), a quiet input (neg), severity/evidence correctness, unknown/ref
   behavior, and whether the empty resource fires. No panics in any rule.
2. **Existing-test attribution**: mapped test functions to rules (ID/type mentions
   + firing/quiet assertion signals) to find which rules already had pos+neg.
3. **Hand verification**: read the `Check`/`CheckAll` of every rule the probe
   could not drive in Critical/High, every unknown/ref-flagged rule, and every
   rule with no attributed test — to separate probe blind spots from real defects.
4. **Fixes + regression tests** for the 27 real defects found (Section 4).
5. **Generated replay suite**: for the 291 rules the probe drove but existing
   tests did not cover, emitted `effectiveness_audit_test.go` replay tests that
   re-execute the probe-discovered witnesses (pos: fire + severity + non-empty
   evidence; neg: quiet; unknown: quiet where the probe observed quiet).
6. **Hand-written tests** for the 29 medium/low rules with no probe witness and
   no existing test, plus regression tests for all 27 fixes.

### Test inventory added by this audit

| Suite | Tests | Result |
|---|---|---|
| Generated replay (`TestEffectivenessReplay_*`) | 291 (aws 76, azure 181, gcp 31, k8s 3) | all pass |
| Hand-written pos+neg + fix regressions (`TestEffectiveness_*`) | 52 (aws 12, azure 29, gcp 11) | all pass |
| Pack registry smoke tests | 6 (one per pack with no replay rules) | all pass |
| **Total new `TestEffectiveness*`** | **349** | **all pass** |

Run: `go test ./internal/rules/... -run 'TestEffectiveness' -count=1`
(349 pass; `GOTMPDIR=$HOME/.cache/go-build-tmp`, Go 1.25.4.)

## 3. Per-pack summary (probe-executed pos+neg / total)

| Pack | Probe pos+neg | Union pass | Fixed |
|---|---:|---:|---:|
| alibaba (ALI) | 11 / 12 | 12 / 12 | 0 |
| aws (AWS) | 392 / 471 | 471 / 471 | 0 |
| azure (AZURE + AZR) | 276 / 292 | 292 / 292 | 22 |
| compose | 5 / 8 | 8 / 8 | 0 |
| docker | 23 / 36 | 36 / 36 | 0 |
| gcp (GCP) | 214 / 280 | 280 / 280 | 5 |
| k8s (K8S) | 19 / 27 | 27 / 27 | 0 |
| oci (OCI) | 6 / 8 | 8 / 8 | 0 |
| supplychain (SC) | 7 / 9 | 9 / 9 | 0 |
| terraform (TF) | 5 / 8 | 8 / 8 | 0 |
| **Total** | **958 / 1,151** | **1,151 / 1,151** | **27** |

Severity/evidence/remediation on the 973 probe-found firing inputs: severity
correct on 973/973; evidence (attribute + actual + expected all non-empty) on
968/973 — the 5 gaps were fixed (Section 4.3); remediation non-empty on
1,151/1,151 (a fallback template guarantees non-emptiness — "non-empty" does
**not** mean "detailed"; see `13_ACCURACY_100_REPORT.md`). Compliance mappings
present on 242/1,151 rules. 526 rules fire on the empty resource (absence-based
rules — expected; see Section 5).

## 4. Rules fixed (27)

No detection was weakened to pass a test, and no rule was deleted. Every fix
below ships with a regression test in `effectiveness_audit_test.go`.

### 4.1 Dead rules revived (3) — previously `return nil` unconditionally

| Rule | Fix |
|---|---|
| AEGIS-AZURE-033 — Storage account without customer-managed key (low) | Now fires when the `customer_managed_key` block is absent (per Title/Description); present-but-unknown stays quiet. |
| AEGIS-AZURE-059 — Subnet without network security group (low) | Converted to `CheckAll`: fires for each `azurerm_subnet` with no `azurerm_subnet_network_security_group_association` referencing it. |
| AEGIS-AZURE-072 — AKS cluster without pod-managed identity (low) | Now fires when no identity mechanism is present (no `pod_identity` block and neither `workload_identity_enabled` nor `oidc_issuer_enabled` true); unknown signals stay quiet. |

**Known fallout — parity expectations need updating (outside this item's paths):**
fixing 033 makes `TestParityRegression` fail on exactly 16 subtests
(`storage-encryption-azure` + `storage-public-azure`, secure+vuln × 4 dialects),
each off by exactly one finding: `AEGIS-AZURE-033|low|azurerm_storage_account`.
Those fixtures' storage accounts have no `customer_managed_key` block, so the
revived rule fires on them. The parity expectations in
`cmd/aegis/scan_parity_test.go` and the fixtures in `benchmark/parity/fixtures/`
need updating (counts +1, and the secure fixtures should gain a
`customer_managed_key` block to remain secure). No other parity subtest is
affected, and no other fix in this audit changes parity output.

### 4.2 Unknown-value contract violations fixed (19)

Pattern: the rule treated a present-but-unknown value the same as an absent
one (`getStringList ok == false`, `getBlocks known == false`, or a helper
conflating unknown with absent) and fired. An unknown value is undecidable and
must stay quiet; only a genuinely absent value may fire (where the rule's
documented semantics say absence is itself the finding).

| Rules | What changed |
|---|---|
| AZURE-058, 060, 091 | `dns_servers` / `service_endpoints` / `categories`: unknown now quiet. |
| AZURE-061, 075, 285, 304 | `auth_settings` / `api_server_access_profile` (+`authorized_ip_ranges`) / `routing_rule` / `custom_parameters`: present-but-unknown block now quiet. |
| AZURE-111, 112, 114 | `logs` block / top-level log flags: unknown now quiet. |
| AZURE-115, 137, 138 | `site_config`: unknown block now quiet. |
| AZURE-141, 147 | `logs` / `blob_properties`: unknown block now quiet. |
| GCP-088, 091 | `auto_create_network` / `enable_logging`: split absent (fires, provider default) from unknown (quiet). |
| GCP-164, 171 | `nodeConfigMetaString` helper no longer conflates an unknown `node_config` block with an absent one (now returns present=true, known=false; the single caller already quiets on that). |

### 4.3 Empty-evidence defects fixed (5)

These rules fired on an empty-string value and reported `Actual == ""`.
Firing behavior is unchanged; the evidence now names the effective value.

| Rule | Evidence `Actual` when the firing value is empty |
|---|---|
| AZURE-051, 088, 089 | `(empty — not enabled)` |
| AZURE-199 | `(empty — provider default is Allow)` |
| GCP-224 | `(empty — parses as 0s)` |

## 5. Adjudicated, NOT fixed (by design)

### 5.1 Unknown/ref "fires" that are not violations (20 rules)

The probe flagged 39 rules whose unknown/ref kitchen-sink input produced a
finding. 19 were the violations fixed in Section 4.2. The other 20 fire for
reasons independent of any unknown *value*:

- **Existence rules (11):** the rule fires on the mere presence of a resource
  type and reads no value — AWS-309, 396, 400, 556, 657, 658, 659; GCP-075,
  147, 151, 202.
- **Companion-absence rules (7):** the rule fires when a *companion resource*
  is missing from the set, not because of any unknown value — AWS-206, 443,
  513, 613; AZURE-102, 108, 124.
- **Explicit-uncertainty findings (2):** AWS-343/344 return a `SeverityInfo`
  `UNCERTAIN` finding (not a violation) when a policy is an unresolvable
  reference — the codebase's deliberate D3 explicit-uncertainty contract. The
  probe counts any finding, so it flagged these; the finding is explicitly
  marked uncertain and is not a hard violation.
- **Absence-with-provider-default rules:** the remaining flagged rules fire on
  genuinely absent values where the provider default is itself the vulnerable
  state (e.g., AZURE-128/230 fire on an absent Entra-ID RBAC block; GCP-088
  fires on absent `auto_create_network` because the default is `true`). The
  probe's all-unknown input leaves those values absent-shaped only where the
  rule's own logic says absence is the finding; unknown *values* are quiet
  after the Section 4.2 fixes. (AZURE-128/230 were probe "no-neg" artifacts —
  both have existing neg tests, e.g. `TestAZURE128_ManagedQuiet`.)

### 5.2 Probe artifacts, not rule defects

- **178 "no-pos" rules:** the probe battery lacks the shape (enum values such
  as `EC2`/`unlimited`/`PriceClass_All`, metadata maps, 2-level nesting beyond
  its top-8 attrs, graph fixtures). Existing tests cover them (Critical/High
  verified by hand; see Section 1 caveat for medium/low).
- **15 "no-neg" rules:** all explained — existence rules (neg = a type the rule
  does not apply to), companion-absence rules (neg = companion present), and
  AZURE-128/230 (existing neg tests; the probe missed the quiet input).
- **5 "evidence-bad" flags:** the probe's first firing candidate used an
  empty-string value; fixed in Section 4.3.
- **K8s timeouts in an earlier probe run:** battery-size overhead, not slow
  rules (direct checks run in microseconds); resolved by capping the battery.

## 6. Boundary / alternate-form / variable behavior

- **Boundary:** every verdict in the CSV rests on a vulnerable + secure pair
  (the boundary), and the probe additionally evaluated the empty resource
  (526 rules fire on empty — absence-based by design) and the all-unknown /
  all-ref inputs for every rule.
- **Alternate config forms:** the probe battery covered block vs. map vs. list
  forms, inline vs. standalone companion resources, and JSON policy strings;
  the replay tests preserve the exact witnessed form per rule.
- **Variable / module / unknown values:** unknown and ref inputs must stay
  quiet except for the by-design cases in Section 5.1. After the Section 4.2
  fixes, no rule fires on an unknown or ref *value* except the two
  `SeverityInfo` UNCERTAIN findings (AWS-343/344), which are explicitly
  marked uncertain rather than violations.

## 7. Reproduction

- Probe (scratch, not a deliverable): binary + sources in the audit work area;
  run `go test ./internal/rules/... -run 'TestEffectiveness' -count=1` for the
  349-test suite (291 replay + 52 hand-written + 6 smoke).
- Full suite: `go test ./internal/... ./cmd/...` passes except the 16
  `TestParityRegression` subtests listed in Section 4.1 (expected fallout of
  the AZURE-033 fix; expectations live outside this item's paths). A
  pre-existing, unrelated build failure in
  `docs/audit/raw/phase6/stage_harness` (two `main` declarations) breaks
  `go test ./...` at the package-list stage; it predates this item and was not
  touched.

## 8. Open items for the parent

1. **Parity expectations** (`cmd/aegis/scan_parity_test.go`,
   `benchmark/parity/fixtures/`): update counts/fixtures for AZURE-033
   (Section 4.1). Outside this item's assigned paths.
2. **Medium/low existing-test attribution** was heuristic (Section 1 caveat);
   the probe-executed 958/1,151 is the measured floor.
3. The probe battery could be extended with per-rule enum values harvested
   from `Check` string comparisons (e.g. `EC2`, `unlimited`) to close the
   178 probe "no-pos" gaps mechanically — not required, since existing tests
   cover them.
