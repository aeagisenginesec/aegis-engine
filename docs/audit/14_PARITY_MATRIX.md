# Cross-Format Semantic Parity Matrix (Item 2)

**Date:** 2026-10-13
**Branch:** `mission/top-tier-validation`
**Rule registry:** 1,151 rules (`aegis doctor`, this branch)
**Scope:** Pulumi fix verification + new cross-format parity scenarios + unsupported-syntax diagnostics.

> **What this document does NOT establish.** The 148 parity cases in
> `benchmark/parity/` plus the scenarios in this report do **NOT** establish
> universal parity across formats. They establish parity for the tested
> controls, the tested resource types, and the tested property shapes.
> Every format has untested corners (see §6 Known limitations); a
> configuration outside the tested set can still diverge. Parity is a
> tested property of specific equivalences, not a blanket guarantee.

## 1. Pulumi fix verification (15 round-2 projects, c056–c070)

The round-2 root cause (all 15 Pulumi YAML projects → 0 findings) was fixed
in `41a8d77` (dual-layout support) and extended in `f7e3cbe` (nested
`properties:` flattening for NSG / Key Vault). Verified on this branch with
a binary built from HEAD: **all 15 projects produce findings; no
zero-finding regression; the fix holds.**

Secure-fixture severity profile (must stay free of critical/high findings):

| Fixture | Profile | Findings | Crit/High | Verdict |
|---------|---------|----------|-----------|---------|
| c058 | secure Azure storage | 11 | 0 | ✅ |
| c063 | secure IAM | 3 | 0 | ✅ |
| c067 | secure Lambda | 5 | 0 | ✅ |
| c069 | secure RDS | 8 | 1 (AEGIS-AWS-540, RDS IAM auth — genuine hardening gap) | ✅ |

Counts vs the `PULUMI_ROOT_CAUSE.md` table, with deltas attributed by
re-running a binary built from `41a8d77` (via `git archive`, no checkout):

| Project | `PULUMI_ROOT_CAUSE` table | `41a8d77` binary (ground truth) | HEAD | Explanation |
|---------|--------------------------|--------------------------------|------|-------------|
| c056 | 7 | 7 | **5** | −2 intentional: `3da23be` suppresses AWS-001/206 on intentionally-public buckets (round-3 adjudication: 24 such findings marked FPs). Adapter still delivers acl/website/policy (AWS-002/104/445 still fire). Not a Pulumi regression. |
| c057 | 13 | 13 | 13 | — |
| c058 | 11 | 11 | 11 | — |
| c059 | 14 | 14 | 14 | — |
| c060 | 3 | 3 | **3** | −3 FPs fixed by `f7e3cbe` flattening (007/038/187 were reading unflattened nested properties; fixture genuinely sets soft-delete/RBAC/Deny) +2 true findings (AZR-005 purge, AZURE-205 firewall rules) +1 AZURE-043 standard-SKU (this item, §3 F2). Net 3, all correct. |
| c061 | 8 | 8 | 8 | — |
| c062 | 4 | 4 | 4 | — |
| c063 | 3 | 3 | 3 | — |
| c064 | 15 | **16** | 16 | Table entry stale; `41a8d77` binary itself yields 16. No change since. |
| c065 | 2 | **3** | 3 | Table entry stale; `41a8d77` binary itself yields 3. No change since. |
| c066 | 22 | 22 | 22 | — |
| c067 | 5 | 5 | 5 | — |
| c068 | 3 | 3 | **5** | +1 AZR-005 purge protection (TP gained by `f7e3cbe` flattening) +1 AZURE-043 standard-SKU (this item, §3 F2). |
| c069 | 8 | 8 | 8 | — |
| c070 | 22 | **21** | 21 | Table entry stale; `41a8d77` binary itself yields 21. No change since. |

**Correction to the prior report:** the `PULUMI_ROOT_CAUSE.md` table has three
stale counts (c064: 15→16, c065: 2→3, c070: 22→21). The re-run `41a8d77`
binary is the ground truth; HEAD matches it on all three. The table should
be read with those three entries corrected.

New Pulumi fixtures (this item, `template:`- and top-level layouts) also
verify in §2: both layouts produce identical findings.

## 2. New cross-format parity scenarios

Method: equivalent security configurations (same vulnerable controls)
authored natively in each format, scanned with the HEAD binary, findings
compared as (rule_id, severity) multisets. Fixture sources live in
`/tmp/aegis-item2/parity/` (scratch; not committed — the committed corpus
in `benchmark/parity/` is unchanged).

### S1 — Key Vault (TF / ARM / Bicep / Pulumi-template / Pulumi-top-level)

| Variant | Result |
|---------|--------|
| Vuln (soft-delete off, purge off, RBAC off, ACLs Allow, all-access policies) | **Exact parity:** all 5 formats → AZR-005, AZURE-007, AZURE-038, AZURE-043, AZURE-186, AZURE-187 |
| Secure (soft-delete 90d, purge on, RBAC on, ACLs Deny + `1.2.3.4/32` allowance, premium-grade SKU still `standard`) | **Exact parity:** all 5 formats → AZURE-043 only (standard SKU, low) |

Before this item's fixes, Pulumi missed 043 + 186 (vuln) and ARM/Bicep
false-positived AZURE-205 (secure) — see §3 F1/F2/F6/F7.

### S2 — NSG open SSH (TF / ARM / Bicep / Pulumi-template)

| Variant | Result |
|---------|--------|
| Vuln (inbound Allow TCP 22 from `0.0.0.0/0`) | **Equivalent conclusion, different rule IDs (modeling divergence, documented):** TF (standalone `azurerm_network_security_rule`) → AZR-003 (high) + AZURE-010 (medium, sensitive port) + AZURE-054 (high). ARM/Bicep/Pulumi (inline `security_rule`) → AZURE-054 (high) + AZURE-244 (high, inline-open rule). SSH-open-to-internet is flagged high in every format. |
| Secure (SSH from `10.0.0.0/8` only) | **Exact parity:** 0 findings in all formats. |

**Remaining divergence D-1 (not fixed):** AZURE-010 (NSG rule open on a
sensitive port) applies only to standalone
`azurerm_network_security_rule` resources; inline rules have no
sensitive-port counterpart (AZURE-244 is the generic inline-open rule).
The high-severity conclusion is identical, so this is a granularity gap,
not a missed control. Recommended follow-up: extend AZURE-010 (or add an
inline variant) to `security_rule` blocks on NSGs; doing so would change
`benchmark/parity/` expectations and needs its own accuracy review, so it
was deliberately left out of this item.

### S3 — S3 public / private (TF / CFN / Pulumi)

| Variant | Result |
|---------|--------|
| Public (public ACL + website + public bucket policy, no SSE, no PAB) | **Exact parity:** all 3 formats → AWS-002, AWS-003, AWS-012, AWS-104, AWS-443, AWS-445, AWS-601. AWS-001/206 correctly suppressed in all 3 by the intentionally-public rule (`3da23be`), including Pulumi where the policy is a YAML mapping. |
| Private (no public evidence, no SSE, no PAB) | **Exact parity:** all 3 formats → AWS-001, AWS-012, AWS-206, AWS-443, AWS-445, AWS-601. |

Before this item's fixes, Pulumi missed AWS-003 (map-valued `policy` never
stringified) and CFN missed AWS-104 via policy-only grants (`!Ref` link
unresolved) — see §3 F3/F4/F5.

### S4 — RDS (TF / CFN / Pulumi)

| Variant | Result |
|---------|--------|
| Vuln (public + unencrypted + no deletion protection + no backups + single-AZ) | **Exact parity:** all 3 formats → 17 identical rule IDs (007, 008, 011, 207, 311, 339, 446, 540, 543, 544, 546, 605, 607, 608, 702, 706, 710). |
| Secure (private + encrypted + deletion protection + 7d backups + multi-AZ) | **Exact parity:** all 3 formats → 12 identical rule IDs. Remaining findings are hardening notes on the secure config (e.g. IAM auth, logging), identical across formats. |

### S5 — Container privileged / root (Dockerfile / Compose / K8s)

Format-specific rule sets by design (no shared rule IDs):

| Format | Config | Result |
|--------|--------|--------|
| Dockerfile (`FROM ubuntu:latest`, `USER root`, no HEALTHCHECK) | 11 DOCKER findings incl. DOCKER-002 (high, root user) | ✅ |
| Compose (`privileged: true`, `user: "0"`) | COMPOSE-001 (high, privileged) + 007 + 008 | ✅ |
| K8s Deployment (`privileged: true`, `runAsUser: 0`, writable rootfs) | K8S-001 (critical, privileged) + 002 (high) + 5 more | ✅ |

Conclusions align (privileged/root flagged in every format). **Divergence by
design:** a Dockerfile has no `privileged` concept (privilege is a runtime
flag), so there is no Dockerfile counterpart to COMPOSE-001 / K8S-001;
likewise Compose/K8s have no image-build rules. Cross-format comparison
for containers is conclusion-level, not rule-ID-level.

## 3. Divergences found and fixed (this item)

All fixes are adapter normalization or link-resolution corrections. No rule
was weakened; every fix is additive (findings gained or false positives
removed) and carries a regression test.

| # | Divergence | Root cause | Fix | Tests |
|---|-----------|------------|-----|-------|
| F1 | Pulumi Key Vault missed AZURE-186 (soft-delete retention) | `softDeleteRetentionInDays` snake-cased to `soft_delete_retention_in_days`; rules read `soft_delete_retention_days` (ARM typemap has the rename; Pulumi lacked it) | `renameAttr` in Pulumi KV block | `TestKeyVaultRetentionAndSkuNormalization` |
| F2 | Pulumi Key Vault missed AZURE-043 (standard SKU) | Pulumi `sku: {name: standard}` map never promoted to `sku_name` (ARM does this for all types; Pulumi did not) | `sku` map `name` → `sku_name` promotion in Pulumi `resource()` | Same test |
| F3 | Pulumi S3 BucketPolicy with a YAML-mapping `policy` missed AWS-003/104 | Rules read `policy` as a JSON string (`getString`); Pulumi kept the mapping as a map | Map-valued `policy` → JSON string (bails out if any part is Unknown, so nothing is fabricated) | `TestMapValuedPolicyStringified`, `TestPolicyWithUnknownNotStringified` |
| F4 | Pulumi-stringified policy docs missed AWS-104 | `policyGrantsPublicRead` matched statement keys case-sensitively (`s["Effect"]`); Pulumi snake-cases keys (`effect`) | Case-insensitive lookup (`lookupMapFold`), same rationale as `policyAllowsPublicPrincipal` | `TestS3Exfiltration_SnakeCasePolicyDoc` |
| F5 | CFN policy/PAB linked via `!Ref` missed AWS-104 / false-positived AWS-206 | `policyBucketAddr` / `pabBucketAddr` handled only `type.name` refs; `linkedBucketAddr` already handled `cfn.resource.X` | Mirror the `cfn.resource.X` branch in both resolvers; add `AWS::S3::PublicAccessBlock` to the CFN typemap (was unmapped → dropped with warning) | `TestPolicyBucketAddr_CFNRef`, `TestPabBucketAddr_CFNRef`, `TestS3BucketPolicyRefAttribution`, `TestS3PublicAccessBlockRefAttribution` |
| F6 | ARM/Bicep Key Vault with `ipRules: [{value}]` false-positived AZURE-205 | Rules read `ip_rules` as a plain string list; ARM/Bicep deliver a list of `{value: …}` maps; `virtualNetworkRules: [{id}]` likewise vs `virtual_network_subnet_ids` | Unwrap `ip_rules` (`value`) and rename+unwrap `virtual_network_rules` → `virtual_network_subnet_ids` (`id`) in ARM `mapResource` (covers Bicep via `BuildResources`) | `TestKeyVaultNetworkAclsUnwrap` (arm) |
| F7 | Same as F6 for Pulumi Key Vault | Pulumi `networkAcls.ipRules: [{value}]` / `virtualNetworkRules: [{id}]` | Same unwrap in Pulumi KV block | `TestKeyVaultNetworkAclsUnwrap` (pulumi) |

Diagnostics fixes (unsupported syntax → warning, §4):

| # | Case | Fix |
|---|------|-----|
| D-F1 | Dockerfile unknown instruction silently ignored | `default:` branch in the instruction switch → warning diagnostic |
| D-F2 | Compose unknown service key silently ignored (e.g. typo'd `priviliged: true` → privileged container scans clean) | Unknown-key warning against a generous Compose-spec allowlist (`x-*` exempt); `parseService` now returns diagnostics |
| D-F3 | ARM expression calling an unknown function silently became Unknown | One warning per unknown function name per template (`knownARMFunction` allowlist incl. `list*` prefix, Bicep `getSecret`/`load*`, and the Bicep adapter's own `[unknown()]` placeholder); unparsable expressions also warn once |

## 4. Unsupported-syntax diagnostics matrix (S6)

| Probe | Before | After (this item) |
|-------|--------|-------------------|
| Bicep `for`-loop resource | Warning: "uses a for-loop; not expanded, skipped" | ✅ unchanged |
| Bicep `module` statement | Warning: "statement module is not supported; skipped" | ✅ unchanged |
| CFN unmapped type `AWS::Foo::Bar` | Warning: "unmapped resource type … skipped"; known bucket still scanned | ✅ unchanged |
| Pulumi `fn::invoke` intrinsic | Warning: "intrinsic fn::invoke is not statically resolvable; treated as unknown" | ✅ unchanged |
| Pulumi YAML invalid syntax | Error diagnostic | ✅ unchanged |
| `.tf.json` (Terraform JSON syntax, unsupported) | Warning via manifests adapter: "unrecognized document … skipped" | ✅ unchanged |
| K8s unknown kind (`kind: FooBar`) | 0 findings, 0 diagnostics | ⚠️ **By design, not a drop:** the document becomes a `k8s_FooBar` resource; no rules apply to that kind — the same treatment as an unruled Terraform type (e.g. `random_pet`). No diagnostic is emitted for unruled kinds in any format. Documented here; not changed. |
| Dockerfile unknown instruction | Silently ignored | ✅ Warning (D-F1) |
| Compose unknown service key / typo'd security key | Silently ignored | ✅ Warning (D-F2) |
| ARM unknown function in a property (`[nosuchfunction('x')]`) | Silently Unknown → no finding, no diagnostic | ✅ Warning (D-F3) |
| ARM unparsable expression | Silently Unknown | ✅ Warning (D-F3) |
| Pulumi TypeScript program (`Pulumi.ts` + `index.ts` only) | 0 findings, 0 diagnostics | ⚠️ **Known silent gap (documented, not fixed):** `.ts` files are never discovered (extension filter), so no adapter ever sees them and no diagnostic can fire. TS/Python/Go/.NET programs are out of scope (need language runtimes; see `docs/PULUMI.md`), but the scan gives the user no hint. Recommended follow-up: a scan-level hint when a directory contains Pulumi program files but no parseable IaC (touches shared CLI behavior; left for a dedicated change). |

Noise validation for D-F3: scanned all 59 eval-corpus + parity-fixture
dirs containing ARM/Bicep/JSON — after allowlist corrections
(`subscriptionResourceId`, `tenantResourceId`,
`managementGroupResourceId`, Bicep `getSecret`/`load*`, Bicep `[unknown()]`
placeholder), **zero spurious warnings** on real templates. The only
warnings fired were on the synthetic typo probes.

## 5. Supported resource types × properties matrix (per format)

Rule registry: **1,151 rules** on this branch. Note:
`benchmark/parity/support-matrix.json` was generated for the earlier
1,185-rule registry (pre-dedup) — its per-rule adapter support is
directionally correct but predates the dedup; regenerate it before citing
exact per-rule numbers.

| Format | Resource-type coverage | Property normalization (highlights) | Test evidence |
|--------|----------------------|-------------------------------------|---------------|
| Terraform (`.tf`, `.tfvars`) | Native reference format. Rules are written against TF attribute names; every rule's `AppliesTo` type is a TF type. | None needed (reference). | Full suite; 148-fixture corpus. |
| CloudFormation (YAML/JSON) | **107** mapped types (`cfnToTF`). Unmapped types → warning + skip. | `propertyRenames` (e.g. `AccessControl`→`acl`, `BucketName`→`bucket`, `MasterUserPassword`→`password`); acronym-aware snake_case; `PolicyDocument`/`AssumeRolePolicyDocument` preserved-case JSON strings; S3 companions synthesized (logging, PAB); `PublicAccessBlock` standalone type added this item (F5). | `cfn_test.go` + parity corpus. |
| ARM (`azuredeploy.json`) | **93** mapped types (`armTypeTable`, longest-prefix child matching). Unmapped → `arm_<sanitized>` fallback type with warning (resource stays visible; no rules apply). | Per-type `propertyRenames` (e.g. KV `softDeleteRetentionInDays`→`soft_delete_retention_days`); `sku.name`→`sku_name`; `publicNetworkAccess` enum→bool; nested `encryption.requireInfrastructureEncryption` promoted; NSG `securityRules[].properties` flattened; KV `ipRules`/`virtualNetworkRules` unwrapped (F6). | `arm_test.go` + parity corpus. |
| Bicep (`.bicep`) | Same as ARM (translates to ARM JSON → `arm.BuildResources`). | Same as ARM. `for` loops / `module` refs / `existing` / `output` skipped with warnings. | `bicep_test.go` + parity corpus. |
| Pulumi YAML (`Pulumi.yaml`) | **157** token mappings (`pulumi/typemap.go`) + sanitized-derivation fallback with warning for unmapped types. TS/Python/Go/.NET out of scope. | Dual layout (root + `template:`-nested); `config:` alias for `configuration:`; camelCase→snake_case; `${…}` pure refs resolved, `fn::*` → explicit Unknown + warning; Azure storage property renames; NSG `securityRules`→`security_rule` + nested-properties flatten; KV flatten + renames (F1/F2/F7); map-valued `policy` → JSON string (F3); `sku.name`→`sku_name` (F2). | `pulumi_test.go` (24 tests) + §1 + §2. |
| Terraform Plan JSON (`.plan.json`) | TF types from `planned_values` (nulls → Unknown; sensitive → redacted). | `resource_changes` intent not analyzed (documented). | `planjson_test.go` + parity corpus. |
| Dockerfile | One `docker_stage` per `FROM` stage. | Multi-stage, ARG/ENV (secret values redacted), `USER`/`HEALTHCHECK`/`ADD`/`RUN` (sudo) tracked; only the final stage ships for runtime rules. Unknown instructions → warning (D-F1). | `dockerfile_test.go` + parity corpus. |
| Compose (`docker-compose.*`, `compose.*`) | One `compose_service` per service. | `image`/`privileged`/`cap_add`/`network_mode`/`pid`/`user`/`ports`/`volumes`/`environment` (secret values redacted). Unknown service keys → warning (D-F2). | `compose_test.go` + parity corpus. |
| K8s manifests (YAML) | Any `apiVersion`+`kind` document becomes `k8s_<Kind>`; **9 kinds have rules**: Pod, Deployment, Service, Ingress, Role, RoleBinding, ClusterRole, ClusterRoleBinding, ConfigMap. Other kinds parse but have no rules (by design, §4). | Whole document becomes attributes; rules navigate `spec` shapes. | `manifests_test.go` + parity corpus. |

### Property-level equivalence notes (where the adapters have to agree)

- **Key Vault:** `purge_protection_enabled`, `soft_delete_enabled`,
  `soft_delete_retention_days`, `enable_rbac_authorization`, `sku_name`,
  `network_acls{default_action, bypass, ip_rules,
  virtual_network_subnet_ids}` — all five formats agree after F1/F2/F6/F7.
- **NSG:** standalone vs inline rule modeling differs (§2 S2, divergence D-1).
- **S3:** `acl`, `website`, `policy` (JSON string), `bucket` link, PAB
  companion — all three formats agree after F3/F4/F5. CFN `AccessControl`
  enum is the supported public-ACL path; CFN `AccessControlPolicy` grant
  lists are **not** translated to `acl` (limitation, §6).
- **RDS:** `publicly_accessible`, `storage_encrypted`,
  `deletion_protection`, `backup_retention_period`, `multi_az` — all three
  formats agree (§2 S4).

## 6. Known limitations (not defects — documented, not fixed here)

- Pulumi TS/Python/Go/.NET programs: out of scope (need language runtimes).
  No diagnostic when a directory contains only such files (§4).
- Pulumi partial string interpolation (`"${var}-suffix"`) is not resolved;
  pure `${var}` references are. Values stay literal (safe).
- Pulumi `fn::*` intrinsics → explicit Unknown + warning (by design).
- CFN `AccessControlPolicy` grant lists not translated to `acl` (use the
  `AccessControl` enum); CFN unmapped types dropped with warning.
- Bicep `for` loops, `module` refs, `existing` resources skipped with warning.
- Plan JSON `resource_changes` intent not analyzed.
- `.tf.json` (Terraform JSON syntax) not supported; manifests adapter warns
  and skips.
- K8s kinds without rules (incl. all CRDs) parse but yield no findings and
  no diagnostic (§4).
- AZURE-010 has no inline-NSG counterpart (divergence D-1, §2 S2).
- IAM policy documents from Pulumi mapping-valued `policy` attributes are
  stringified with snake_cased keys; IAM rules using `policyStatements`
  match `Statement` case-insensitively but read inner keys case-sensitively,
  so some IAM conclusions on Pulumi-authored mapping policies may still be
  missed. S3 policy parsing was fixed (F4); the IAM equivalent is a
  recommended follow-up (rule-side case-insensitive statement-key reads).
- ARM `reference()` / `list*()` / `resourceGroup()` etc. values are
  legitimately Unknown and silent by design; only genuinely unknown
  function names warn (D-F3).

## 7. Reproduction

```bash
cd ~/workspace/aegis-engine
export PATH=~/workspace/toolchain/go/bin:$PATH
export TMPDIR=~/workspace/.tmp-item2   # shared /tmp is a small tmpfs
go build -o /tmp/aegis-item2/aegis ./cmd/aegis/
# Pulumi verification (15 fixtures)
/tmp/aegis-item2/aegis scan docs/audit/raw/final-eval/corpus/c056/ --format json
# Parity + regression suites
go test ./internal/adapter/... ./internal/rules/aws/ ./cmd/aegis/ -run 'TestParity|TestS3|TestKeyVault|TestPolicy|TestPab|TestUnknown|TestMapValued'
go test ./internal/...
```

## 8. Performance note (quality gate)

A quality-gate run on the mixed working tree (six workers' uncommitted
changes + heavy sibling benchmark load) failed its performance gate once
(p95 536.9 ms vs 500 ms threshold). That reading is **not** attributable
to this item: a direct A/B on the same loaded VM, 5 back-to-back full
scans of `~/workspace/terraform/vuln-200` — committed-HEAD baseline vs
HEAD + this item's files — gave medians of 520 ms (baseline) vs 477 ms
(this item), i.e. no slowdown. The gate failure is consistent with
shared-VM load variance (sibling Trivy/Checkov sweeps were running
concurrently). Re-run the gate on a quiet machine before treating any
single perf reading as signal.

## 9. Files changed (this item)

> Shared-tree note: six workers edit this branch concurrently. Several of
> the files below also contain a sibling worker's concurrent
> parser-hardening changes (e.g. Pulumi work-budget / alias-cycle guards,
> ARM variable-cache memoization, Compose non-mapping-service warning,
> Terraform lenient-parse repairs) in *different hunks*. Only the hunks
> described in §3/§4 are this item's; the sibling hunks are not claimed
> here and were not modified by this item.

- `internal/adapter/pulumi/pulumi.go` + `pulumi_test.go` — F1/F2/F3/F7
  (KV renames, `sku_name` promotion, `policy` stringification, KV
  network-ACL unwrap) + 4 regression tests.
- `internal/adapter/arm/arm.go` + `arm_test.go` — F6 (KV network-ACL
  unwrap) + D-F3 (unknown-function / unparsable-expression warnings) + 3
  regression tests.
- `internal/adapter/cloudformation/typemap.go` + `cfn_test.go` — F5
  (`AWS::S3::PublicAccessBlock` mapping) + 2 regression tests.
- `internal/adapter/dockerfile/dockerfile.go` + `dockerfile_test.go` — D-F1
  (unknown-instruction warning) + 1 regression test.
- `internal/adapter/compose/compose.go` + `compose_test.go` — D-F2
  (unknown-key warning) + 1 regression test.
- `internal/rules/aws/attack_paths.go` + `attack_paths_test.go` — F4
  (case-insensitive statement keys for AWS-104) + F5 (`cfn.resource.X` in
  `policyBucketAddr`) + 3 regression tests.
- `internal/rules/aws/coverage2.go` — F5 (`cfn.resource.X` in
  `pabBucketAddr`).
- `docs/audit/14_PARITY_MATRIX.md` — this file.
