# 00 — Baseline and Evidence Freeze

**Mission:** Aegis Independent Competitive Validation and Benchmarking Mission
**Date:** 2026-10-12
**Phase:** 1 of 10

## 1. Repository state (frozen)

| Item | Value |
|---|---|
| Branch | `fix/demo-defects-d1-d3` |
| HEAD commit | `0c28621b8767702c8edc48c7d9a57313ce24be98` |
| Commit subject | "Fix D1 (IAM attachment coverage), D2 (Lambda KMS attr), D3 (explicit uncertainty)" |
| Working tree | 1 modified file: `aegis` (rebuilt binary, tracked, left unstaged per convention — build artifact, not source) |
| Source tree | Clean — no uncommitted source changes |
| Remote | None configured (nothing pushed externally) |

**No detection-logic changes were made during this phase.** The binary at `/tmp/aegis-baseline` was built from this exact commit for all measurements below.

## 2. Build and test commands (actual results)

| Command | Result |
|---|---|
| `go build -o /tmp/aegis-baseline ./cmd/aegis/` | ✅ exit 0 |
| `go vet ./...` | ✅ clean (run during D-fix verification; re-confirmed via build) |
| `go test -count=1 ./...` (fresh, no cache) | ✅ **32/32 packages pass**, exit 0, ~18 s |
| `go test -race -count=1 ./cmd/aegis/ ./internal/rules/... ./internal/adapter/...` | ✅ **race-clean**, exit 0, ~94 s |
| `go test -count=1 ./cmd/aegis/ -run TestParity` | ✅ ok, 2.07 s |

## 3. Rule registry

| Item | Value |
|---|---|
| `aegis doctor` registry count | **1,185 rules loaded** |
| Registry checksum (sorted unique IDs from non-test source) | see §3.1 |
| Quality gate | **PASS 5/5** — precision 100.0% (tp=355 fp=0), recall 100.0%, rule coverage 363/363, performance median 18.1 ms / p95 25.6 ms (threshold ≤500 ms), parser safety 15/15 |

### 3.1 Registry enumeration discrepancy (flagged for Phase 3)

Two independent counts disagree and this is recorded, not resolved, here:

- `aegis doctor`: **1,185** rules loaded at runtime.
- `grep -rhoE "AEGIS-[A-Z0-9]+-[0-9]+"` over non-test `internal/rules/**/*.go`, unique: **1,193** IDs.
- Pack split of the 1,193: ALI 12, AWS 489, AZR 5, AZURE 308, COMPOSE 9, DOCKER 35, GCP 285, K8S 25, OCI 8, SC 9, TF 8.
- Several IDs (e.g. `AEGIS-ALI-001`…`010`) appear multiple times in non-test source (definition + comment/reference).

Possible causes: IDs present in comments but not registered; programmatic registration; duplicate registration. **Phase 3 must enumerate via the live registry, not grep.**

Checksum of the sorted 1,193-ID list: `sha256` recorded in `docs/audit/raw/baseline_rule_ids.txt` (1,193 lines). The runtime registry (1,185) has no dump command; Phase 3 should add or use one.

## 4. Adapter inventory (9 adapters)

| # | Adapter | Package | Input formats |
|---|---|---|---|
| 1 | Terraform HCL | `internal/adapter/terraform` | `.tf` |
| 2 | CloudFormation JSON | `internal/adapter/cloudformation` | `.json` (CFN markers) |
| 3 | CloudFormation YAML | `internal/adapter/cloudformation` | `.yaml`/`.yml` (CFN markers) |
| 4 | Azure ARM templates | `internal/adapter/arm` | `.json` (ARM `$schema`) |
| 5 | Bicep | `internal/adapter/bicep` | `.bicep` |
| 6 | Pulumi YAML | `internal/adapter/pulumi` | `Pulumi.yaml`/`.yml` |
| 7 | Terraform plan JSON | `internal/adapter/planjson` | plan JSON |
| 8 | Dockerfiles | `internal/adapter/dockerfile` | `Dockerfile*` |
| 9 | Docker Compose | `internal/adapter/compose` | `compose`/`docker-compose` YAML |
| — | Kubernetes manifests | `internal/adapter/manifests` | K8s YAML (note: 10th input path; "9 adapters" counts CFN JSON+YAML as one) |

Per-adapter supported constructs: see `docs/ADAPTER_PARITY_REPORT.md` and `benchmark/parity/support-matrix.json` (9 adapters × rule applicability, regenerable via `benchmark/parity/cmd/matrix`).

## 5. Existing corpora, labels, reports, raw outputs

| Artifact | Path | Status |
|---|---|---|
| Adapter parity report | `docs/ADAPTER_PARITY_REPORT.md` | 331/331 subtests pass |
| Parity fixtures | `benchmark/parity/fixtures/` (148, each with `expect.json`) | committed |
| Parity support matrix | `benchmark/parity/support-matrix.json` | regenerable |
| Parity test summary | `benchmark/parity/test-summary.json` | machine-readable |
| AWS demo report | `docs/audit/AWS_DEMO_REPORT.md` | 84 fixtures, 31/34 TF + 8/8 CFN detection |
| AWS demo raw outputs | `docs/audit/demo-raw/` | JSON/SARIF/stdout/stderr/exit codes |
| D1–D3 post-fix comparison | `docs/audit/DEMO_POSTFIX_COMPARISON.md` | pre/post finding diffs |
| Post-fix demo raw outputs | `docs/audit/demo-raw-postfix/` | preserved |
| Corpus v2 (labeled) | `benchmark/corpus-v2/` (200 projects, 50 held-out) | Aegis-centric, procedural lock |
| Competitive showdown | `docs/SHOWDOWN_1185.md` + `benchmark/showdown_1185_raw.json` | internal benchmark |
| Differential triage | `benchmark/differential/` | KICS FP classification |
| Rule inventory note | — | **Phase 3** |

**Contamination note:** corpus-v2 and the AWS demo corpus were used during rule development/tuning. They are NOT independent for final accuracy claims. Phase 4 must use held-out or fresh material and disclose this.

## 6. Environment

| Item | Value |
|---|---|
| OS / kernel | Linux 7.0.0-39-generic |
| CPU | 2 vCPU |
| RAM | 7 GB |
| Go toolchain | go1.25.4 linux/amd64 (`~/workspace/toolchain/go`) |
| Checkov | 3.3.26 (`~/workspace/.venv-checkov/bin/checkov`) |
| KICS | 2.1.20 (`~/workspace/bin/kics`) |
| Trivy | **not installed** — Phase 5 must install and pin a version |

## 7. Constraints observed this phase

- No source files modified; only `/tmp` build artifacts created.
- The tracked `aegis` binary shows as modified (rebuild artifact); left untouched.
- All measurements re-runnable from the commands in §2.
