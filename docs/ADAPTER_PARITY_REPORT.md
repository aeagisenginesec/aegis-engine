# Aegis Adapter Semantic Parity Audit Report

**Date:** 2026-10-12
**Baseline commit:** `4898204fb83b6795a9b1f9303df55169f625d01d` ("Add ARM + Bicep adapters")
**Rule registry:** 1,185 rules
**Status:** ✅ PASS — all 331 parity subtests green, quality gate PASS

## Executive Summary

This audit validated semantic equivalence across Aegis's nine input adapters by building a 148-fixture equivalence corpus and running differential parity tests. The audit found and fixed **7 confirmed defects** that caused cross-format finding discrepancies. After fixes, all equivalent configurations produce equivalent security outcomes.

**Key result:** Before fixes, 39 cross-format parity gaps were detected. After fixes, **0 gaps** remain.

## Phase 1 — Baseline

Recorded in `benchmark/parity/baseline/`:
- Git commit: `4898204fb83b6795a9b1f9303df55169f625d01d`
- `aegis doctor`: 1,185 rules, all checks pass
- `aegis quality-gate`: 5/5 PASS
- `go test ./...`: 32/32 packages pass
- Per-adapter IR mapping documentation (3 files, ~95KB total)

## Phase 2 — Equivalence Corpus

**148 fixtures** in `benchmark/parity/fixtures/`, organized as `<control>-<cloud>/<variant>/<format>/`:

| Control | AWS | Azure | GCP | Other |
|---------|-----|-------|-----|-------|
| storage-public | tf, cfn-json, cfn-yaml, pulumi, planjson | tf, arm, bicep, pulumi | tf, pulumi | — |
| storage-encryption | 5 formats | 4 formats | 2 formats | — |
| network-ingress | 5 formats | 4 formats | 2 formats | — |
| iam-wildcard | 5 formats | — | — | — |
| database-public | 5 formats | 4 formats | 2 formats | — |
| logging | 5 formats | — | — | — |
| secrets-hardcoded | 5 formats | 4 formats | — | — |
| defaults-absent | 5 formats | — | — | — |
| unknown-values | 5 formats | 4 formats | — | — |
| container | — | — | — | dockerfile, compose, manifests |

Each fixture includes input files + `expect.json` with normalized findings, diagnostics, determinism hash, and completeness status.

## Phase 3 — Differential Tests

`cmd/aegis/scan_parity_test.go` implements:
1. **TestParityRegression**: current output matches recorded expectations (148 fixtures)
2. **TestParityDeterminism**: 3 runs → identical finding hash (148 fixtures)
3. **TestParityCrossFormat**: within one control+variant, all formats produce identical finding multisets (35 multi-format control groups; 19 single-format groups have no cross-format peer and are covered by regression + determinism)

**Result:** 331/331 subtests PASS (148 regression + 148 determinism + 35 cross-format; 3 parent tests also pass).

## Phase 4 — Format-Specific Findings

### CloudFormation
- ✅ Intrinsic functions (Ref, Join, Sub, GetAtt) resolve correctly or mark Unknown
- ✅ Conditions/Mappings handled with explicit diagnostics
- ⚠️ Unmapped types are dropped with warning (documented limitation)

### ARM
- ✅ Expressions, parameters, variables resolve correctly
- ✅ API-version-dependent properties mapped via typemap
- ✅ Nested `encryption.requireInfrastructureEncryption` now promoted

### Bicep
- ✅ Native parser handles common constructs
- ✅ Function calls in param defaults now handled (was dropping resources)
- ⚠️ `for` loops, `module` refs skipped with warning (documented)

### Pulumi YAML
- ✅ `fn::` intrinsics marked Unknown with diagnostics
- ✅ Resource refs now qualified as `type.name.attr` for cross-adapter compatibility
- ⚠️ TypeScript/Python/Go programs out of scope (documented)

### Plan JSON
- ✅ Planned values converted; nulls → Unknown; sensitive → redacted
- ⚠️ `resource_changes` intent not analyzed (documented)

### Docker/Compose/Manifests
- ✅ Multi-stage, ARG/ENV, capabilities, privileged mode all handled
- ✅ Each format has distinct rules (not cross-compared)

## Phase 5 — Defects Fixed

### DEFECT-1: CFN property name mapping (24 parity gaps)
**Root cause:** Generic snake_case produced wrong attribute names (`AccessControl` → `access_control` instead of `acl`; `BucketName` → `bucket_name` instead of `bucket`; `MasterUserPassword` → `master_user_password` instead of `password`).
**Fix:** Added `propertyRenames` table in `internal/adapter/cloudformation/props.go` mapping CFN names to TF attribute names for S3, RDS, IAM, EC2.
**Tests:** Updated `cfn_test.go`; parity fixtures validate.

### DEFECT-2: CFN snakeCase acronym mangling
**Root cause:** Naive snakeCase converted `KMSMasterKeyID` → `k_m_s_master_key_i_d`.
**Fix:** Acronym-aware snakeCase in `internal/adapter/cloudformation/intrinsics.go` (`KMSMasterKeyID` → `kms_master_key_id`).
**Tests:** Parity fixtures; existing unit tests pass.

### DEFECT-3: CFN null → Known:true
**Root cause:** YAML `!!null` became `Known:true, Raw:nil`, inconsistent with terraform/planjson (Unknown).
**Fix:** Changed to `Known:false` in `internal/adapter/cloudformation/cfn.go`.
**Tests:** Parity `unknown-values` fixtures.

### DEFECT-4: CFN IAM policy key casing
**Root cause:** Policy document keys were snake_cased (`Statement` → `statement`), breaking IAM rules that expect standard casing.
**Fix:** Added `jsonStringPreserveCase` in `intrinsics.go`; used for `PolicyDocument` and `AssumeRolePolicyDocument`.
**Tests:** `iam-wildcard` parity fixtures (6 rules now fire correctly).

### DEFECT-5: Bicep parser drops resources on function-call param defaults
**Root cause:** `parseIdentOrCall` returned immediately after `parseCall` without consuming `.prop` suffixes, causing parse failure on `resourceGroup().location`.
**Fix:** Continue with suffix loop after function calls in `internal/adapter/bicep/bicep.go`.
**Tests:** Bicep parity fixtures; `arm vs bicep` gaps eliminated.

### DEFECT-6: ARM/Pulumi nested encryption not promoted
**Root cause:** `encryption.requireInfrastructureEncryption` (nested) wasn't mapped to top-level `infrastructure_encryption_enabled` that Azure rules check.
**Fix:** Added promotion logic in `internal/adapter/arm/arm.go` and `internal/adapter/pulumi/pulumi.go`.
**Tests:** `storage-encryption-azure` parity fixtures.

### DEFECT-7: Pulumi resource refs not qualified
**Root cause:** Refs like `logBucket.id` couldn't be resolved by rules expecting `aws_s3_bucket.logBucket.id`.
**Fix:** Track resource name → type mapping; qualify refs in `internal/adapter/pulumi/pulumi.go`.
**Tests:** `logging` parity fixtures; updated `pulumi_test.go`.

### Additional fixes
- **ARM `publicNetworkAccess` enum → boolean** conversion for MSSQL servers
- **ARM security rule `properties` flattening** for NSGs
- **Pulumi `securityRules` → `security_rule`** rename; **`allows` → `allow`** for GCP firewalls
- **CFN S3 logging companion synthesis** (`aws_s3_bucket_logging` resource)
- **CFN ACL enum normalization** (`PublicRead` → `public-read`)

## Phase 6 — Acceptance Criteria

- ✅ Every cross-format equivalence case has explicit expected results (148 expect.json)
- ✅ All tested equivalent configs produce equivalent outcomes (0 gaps)
- ✅ All discrepancies fixed or documented
- ✅ Secure fixtures produce no unexplained findings
- ✅ Unknowns and parse failures remain visible in diagnostics
- ✅ Evidence and resource identity survive the pipeline
- ✅ Determinism (3× hash), regression, quality gate all pass
- ✅ Performance: p95 34.8ms (well under 500ms threshold)

## Deliverables

1. ✅ `docs/ADAPTER_PARITY_REPORT.md` (this file)
2. ✅ `benchmark/parity/fixtures/` — 148 versioned fixtures
3. ✅ `cmd/aegis/scan_parity_test.go` — automated differential tests
4. ✅ `benchmark/parity/support-matrix.json` — per-adapter × per-rule matrix (1,185 rules), regenerable via `benchmark/parity/cmd/matrix` (`go run ./benchmark/parity/cmd/matrix -root .`)
5. ✅ Regression tests for all 7 defects (in adapter `*_test.go` + parity fixtures)
6. ✅ `benchmark/parity/test-summary.json` — machine-readable summary

## Known Limitations (not defects)

- CFN unmapped types are dropped with warning (by design; typemap covers 101 types)
- Bicep `for` loops and `module` refs skipped with warning
- Pulumi TypeScript/Python/Go out of scope (needs language runtimes)
- Plan JSON `resource_changes` intent not analyzed
- `.tf.json` (Terraform JSON syntax) not yet supported — **deferred to follow-up**
- Container formats (Dockerfile/Compose/K8s) have distinct rule sets, not cross-compared

## Reproduction

```bash
cd ~/workspace/aegis-engine
export PATH=~/workspace/toolchain/go/bin:$PATH
go build -o /tmp/aegis-parity ./cmd/aegis/
python3 benchmark/parity/record.py --aegis=/tmp/aegis-parity
go test ./cmd/aegis/ -run 'TestParity' -v
go test ./...
go run ./benchmark/parity/cmd/matrix -root .   # regenerates support-matrix.json
/tmp/aegis-parity quality-gate
```

## Verification Notes (2026-10-12, post-audit re-verification)

- Re-ran the full audit battery at the audit commit with Go 1.25.4: `aegis doctor` ✅, quality gate 5/5 PASS (precision 100%, recall 100%, 363/363 critical/high rules tested, p95 36.3ms), parity subtests 331/331, full suite 32/32 packages green, `TestParityCrossFormat` also green under `-race`.
- Corrected the test count: the original "334" included the 3 parent test nodes; the precise subtest total is **331** (148 + 148 + 35).
- Added the missing matrix generator (`benchmark/parity/cmd/matrix/main.go`) — the committed `support-matrix.json` referenced it via `generated_by` but the program was never committed. The generator reproduces 1184/1185 rule entries byte-identically; the single diff was a data bug in the original file (AEGIS-SC-005's `matched_types` listed attribute names instead of resource types — its `AppliesTo` returns true for every type), which the regenerated file corrects.
- Refreshed `benchmark/parity/test-summary.json` with exact pass/fail/skipped counts and the documented exclusion list.
