# Aegis v2.3.0 — Release Blueprint

**Release:** v2.3.0 — "The Five-Agent Test Release"
**Date:** 2026-11-24
**Previous release:** v2.2.0 (2026-10-22)
**Rule count:** 1,140 (net zero: one duplicate removed, one new rule added)
**Quality gate:** PASS — precision 100%, recall 100%, rule-coverage 355/355, p95 61.8ms

## 1. Why this release exists

On 2026-11-24, all five ObsidianX cloud-engineer specialist agents
(CSPM, DevSecOps, SOC, IAM, Compliance) ran a complex test of Aegis
v2.2.0 — a tool evaluation of Aegis itself against its own fixtures,
benchmarks, and controlled snippets. Every item in this release answers
one of their findings. The agents' unanimous verdict on v2.2.0 was:
strong, fast, accurate — with one confirmed bug and a set of gaps.

## 2. Findings → fixes (traceability matrix)

| # | Agent | Finding | Fix in v2.3.0 | Severity |
|---|---|---|---|---|
| 1 | CSPM | Cross-file address-collision suppression: S3 encryption (001) and public-access-block (206) findings silently vanish when another file reuses the same resource address with a public policy | `linkedBucketAddr` / `linkedTargetBucketAddr` return no link when a bucket reference is ambiguous (multiple in-scope matches). Fail-safe: ambiguous links suppress nothing. Legitimate cross-file correlation (unique addresses) unaffected. | **Bug — fixed** |
| 2 | IAM | Duplicate rule: access-key PGP flagged twice (552 High, 668 Low) | Removed AEGIS-AWS-668; kept 552. Ported 668's better description into 552; fixed 552's remediation text (it wrongly described key rotation instead of `pgp_key`). | Fixed |
| 3 | IAM | No MFA-condition check on admin access | New rule AEGIS-AWS-859 (Medium): fires on open trust (`Principal "*"`) or admin policy (`Action "*"` / `iam:*`) with no Condition requiring `aws:MultiFactorAuthAge` / `aws:MultiFactorAuthPresent`. | Added |
| 4 | IAM | `NotAction` / `NotResource` policies silently skipped | Documented in code on the shared `policyStatements` parser: a broad grant via `NotAction` is silently missed — a deliberate soundness trade-off, not proof of safety. Full handling is deferred (see §5). | Documented |
| 5 | CSPM | Azure rule-prefix inconsistency (`AEGIS-AZR-*` vs `AEGIS-AZURE-*`) | Renamed AZR-001/002/003/005 → AZURE-001/002/003/005 (22 files). AZR-004 remains only as a deprecated-mapping pointer pinned by migration tests. | Fixed |
| 6 | CSPM | Benchmark manifest stale (scenario 07 expects 005, scenario 10 expects 102) | Manifest updated: 07 → 604 (005 deliberately fires only on attached SGs), 10 → 666 (AWS-managed `AdministratorAccess`). Secure 07 fixture given a `description` on the SG and its egress rule so 604 stays silent there (re-test catch, 2026-11-24). All 34 scenarios match, 0 mismatches. | Fixed |
| 7 | Compliance | Single-framework JSON omits posture summary (`compliance_summaries: null`) | Single-framework mode now sets `compliance_summaries` to a one-element array, same shape as `--compliance=all`. | Fixed |
| 8 | Compliance | SARIF is compliance-blind (no framework/control tags) | Results and rule metadata now carry `properties.tags` with `Framework:Control` entries (e.g. `CIS-AWS-1.5:2.1.1`). | Fixed |
| 9 | Compliance | No SBOM generation for scanned projects | Deferred — see §5. `SBOM.md` remains Aegis's own dependency SBOM only. | Deferred |
| 10 | Compliance | `docs/COMPLIANCE.md` stale (3 frameworks / 91 rules vs real 10 / 943) | Rewritten with all 10 frameworks and verified counts. | Fixed |
| 11 | Compliance | `docs/COVERAGE_MATRIX.md` dated 2026-10-11, AWS-only, 245 rules | Updated to the 1,140-rule inventory, marked current for v2.3.0. | Fixed |
| 12 | DevSecOps | SARIF results carry no `partialFingerprints` | Every result now carries a stable SHA-256 fingerprint (`aegis/v1`, from rule + resource + file + line), verified identical across runs. | Fixed |
| 13 | DevSecOps | `aegis fix` S3 versioning patch uses deprecated inline `versioning {}` block | Fixer now proposes a separate `aws_s3_bucket_versioning` resource. Guards against duplicating an existing versioning resource; CRLF files handled. | Fixed |
| 14 | CSPM | `aegis scan` requires a directory (single file exits 2) | Single files accepted (`aegis scan main.tf`). `fix` still requires a directory. Symlinks/non-regular files rejected; nonexistent targets error cleanly. | Fixed |
| 15 | DevSecOps | Scan outputs in the scanned dir are parsed as manifests | `out.json`, `out.sarif`, `out.html`, `aegis.json`, `aegis.sarif` are now skipped when collecting scan targets below the root (an explicitly named file is still scanned). | Fixed |
| 16 | SOC | Attack-path remediation quality inconsistent (104 specific, 105 generic) | Deferred — see §5. | Deferred |
| 17 | SOC | No native SIEM/SOAR webhook output | Deferred — JSON/SARIF piping is the supported path; `aegis serve` exists for SOAR integration. | Deferred |
| 18 | SOC | Older `benchmark/detect_results.json` contradicts the live gate (FP=60 vs FP=0) | Deferred — needs the maintainer to confirm which benchmark file is authoritative. | Deferred |
| 19 | IAM | Kill chains require a network/reference edge; IAM-permission reachability not modeled | Deferred — see §5. Deliberate conservative design ("chains NEVER invent hops"). | Deferred |
| 20 | IAM | `fix` never patches IAM, even with `--force` | By design (safe default — auto-editing IAM policies is dangerous). Documented, not changed. | By design |

## 3. What changed, file by file

| Area | Files | Change |
|---|---|---|
| Suppression fix | `internal/rules/aws/helpers.go` | `linkedBucketAddr`, `linkedTargetBucketAddr`: ambiguity → no link |
| IAM dedup | `internal/rules/aws/iam_deep.go`, `coveragegaps.go`, `internal/rules/compliance.go`, `.aegis/baseline.json` | Removed 668; improved 552 |
| MFA rule | `internal/rules/aws/iam_deep.go`, `pack.go`, `iam_deep_test.go`, `internal/regression/testdata/AEGIS-AWS-859/` | New rule 859 + 8 unit tests + regression fixtures |
| Azure rename | `internal/rules/azure/*.go`, `internal/rules/compliance.go`, `ruleidcheck.go`, `remediation.go`, benchmarks, docs | AZR → AZURE (4 rules, 22 files) |
| SARIF | `internal/report/report.go`, `report_test.go` | Compliance tags + partialFingerprints + 2 new tests |
| JSON summary | `cmd/aegis/main.go`, `cmd/aegis/scan_pulumi_test.go` | Single-framework `compliance_summaries` populated |
| Fix command | `internal/remediation/fixers.go`, `fixers_test.go` | Standalone versioning resource; CRLF fix |
| Single-file scan | `cmd/aegis/main.go`, `cli_audit_test.go`, `main_test.go` | `checkScanTarget`; 4 new tests |
| Output exclusion | `internal/discovery/discovery.go`, `discovery_test.go` | `outputFileNames` skip set; 2 new tests |
| Manifest | `tests/demos/aws-security-demo/manifest.json` | Scenarios 07, 10 updated with notes |
| Docs | `docs/COMPLIANCE.md`, `docs/COVERAGE_MATRIX.md` | Rewritten / updated to 1,140-rule reality |
| Version | `internal/version/version.go`, `cmd/aegis/cli_audit_test.go`, `action.yml`, `CHANGELOG.md` | 2.2.0 → 2.3.0 |

## 4. Verification (all green before release)

- `go build ./...` — OK; `go vet ./...` — clean; `gofmt` — clean.
- `go test ./...` — **0 failures** (full suite).
- `aegis doctor` — all checks passed, 1,140 rules loaded.
- `aegis quality-gate` — **PASS**: precision 100.0% (tp=355, fp=0, fn=0),
  recall 100.0% (tp=355, fp=0, fn=0), rule-coverage 355/355,
  performance median 18.8ms / p95 61.8ms, parser-safety 15/15.
- Fix-by-fix verification (integrated binary `/tmp/aegis-2.3.0`):
  - Bug repro (files 02+03 together): 001 and 206 both fire (were missing).
  - IAM dedup: access key with no `pgp_key` → exactly 1 finding (552).
  - MFA rule 859: fires on the 2 no-MFA resources only.
  - SARIF: 14/19 results carry compliance tags; 19/19 carry fingerprints.
  - Single-framework JSON: `compliance_summaries` has 1 entry.
  - Single-file scan: `aegis scan main.tf` returns 6 findings (was exit 2).
  - Demo manifest: all 34 scenarios match, 0 mismatches.

## 4b. Agent re-test of v2.3.0 (2026-11-24, after the build)

All five agents re-tested the release binary and confirmed every fix:

| Agent | Items | Result |
|---|---|---|
| CSPM | 6 | 5 PASS + 1 PARTIAL — scenario 07: the secure fixture's SG also lacked a `description`, so 604 fired on both sides and the scenario did not discriminate. Fixed by adding a `description` to the secure 07 fixture's SG and egress rule; re-verified 0 findings on secure, 604 fires on vulnerable. Strict per-scenario check now 34/34 (scenarios 29/30 fire only as info-severity UNCERTAIN diagnostics on secure, per the manifest's own semantics). |
| DevSecOps | 6 | All PASS — versioning fixer proposes a separate `aws_s3_bucket_versioning` resource and `--apply` clears 012 with 0 new findings; single-file scan works; empty `out.json` no longer errors; SARIF fingerprints 19/19 stable across runs; quality gate PASS; Action default now v2.3.0. |
| SOC | 6 | All PASS — SARIF tags 14/19 results; fingerprints 19/19 stable; quality gate PASS (p95 84.0ms); golden files exact match (6/6, 7/7, 21/21); corpus recall 99.17% (same single deliberate FN as v2.2.0); attack paths 629/105 fire on their topologies. |
| IAM | 6 | All PASS — 668 gone, exactly 1 PGP finding (552); rule 859 fires on the 2 no-MFA resources and stays silent on the 2 MFA-gated ones; T1–T6 all catch correctly; 552 remediation fixed; NotAction blind spot documented in code. |
| Compliance | 7 | All PASS — single-framework JSON summary present; SARIF tags 26/32 results; docs refreshed; quality gate PASS; all 10 frameworks report posture; waiver governance un-regressed; deferred items honestly documented. |

## 5. Deferred / by design (not in v2.3.0)

- **SBOM generation for scanned projects** (Compliance #9): no `--sbom`
  flag; needs a new output format (SPDX/CycloneDX) and a dependency
  graph. Candidate for v2.4.0.
- **IAM-permission-based kill-chain links** (IAM #19): modeling
  `s3:*` on `*` as a chain link requires IAM reachability analysis in
  the graph builder. Deliberate conservative design today; a v2.4.0
  feature, gated on false-positive measurement.
- **`NotAction` / `NotResource` handling** (IAM #4): parsing these
  correctly requires policy-evaluation semantics, not just linting.
  Documented in code; a v2.4.0 research item.
- **Attack-path remediation consistency** (SOC #16): rule 105's
  remediation is generic boilerplate vs 104's specific SOC-actionable
  text. A content pass, not a code change — v2.4.0.
- **SIEM/SOAR webhook output** (SOC #17): JSON/SARIF piping is the
  supported path today; a native webhook is a v2.4.0 feature.
- **Benchmark file authority** (SOC #18): `detect_results.json`
  (FP=60) contradicts `heldout_results.json` and the live gate (FP=0).
  Needs the maintainer to confirm which is authoritative and delete or
  regenerate the stale one.
- **CIS coverage is a subset by design** (12/60 AWS controls): most
  missing controls need live-cloud evidence (CloudTrail, IAM credential
  reports, CloudWatch alarms), not statically provable from Terraform.
  The posture report covers the mapped controls, not the full benchmark.
- **IAM `fix` stays detect-only** (IAM #20): auto-editing IAM policies
  is dangerous; the safe default stands.

## 6. CI/CD pipeline (how this release ships)

### CI — `.github/workflows/ci.yml` (on push/PR to main, master, mission/**)
1. Build with release ldflags (version stamp from `internal/version`).
2. `go vet` + `gofmt` check.
3. Full test suite (`go test ./...`).
4. Race tests on sensitive packages.
5. `aegis quality-gate` (precision/recall/coverage/perf/parser-safety).
6. Determinism check: scan the multi-cloud fixture 5×, outputs must be
   byte-identical.
7. Upload binary artifact.

### CD — `.github/workflows/release.yml` (on tag `v*.*.*`)
1. **Verify tag == version const** — the job fails if the tag does not
   match `internal/version.Version`. A release can never ship a binary
   that reports the wrong version.
2. Full test suite on the release commit.
3. Cross-compile linux/darwin/windows (amd64+arm64, windows amd64 only)
   with BuildDate + Commit stamped in.
4. SHA256SUMS.txt; publish a GitHub Release with all binaries attached.

### GitHub Action — `action.yml`
- Default version bumped to `v2.3.0`. Downloads the binary from the
  release and verifies it against the published SHA256SUMS.

### Release steps (this version)
1. ✅ All fixes implemented and verified (see §4).
2. ✅ Version bumped to 2.3.0 (`internal/version`, test pins, `action.yml`).
3. ✅ CHANGELOG entry written.
4. Tag `v2.3.0` → triggers `release.yml` → GitHub Release with
   multi-platform binaries.
5. Verify the release: download the linux-amd64 binary, run
   `--version` (must report 2.3.0) and `doctor` (1,140 rules).

## 7. Agent requirements compliance

Each of the five agents' requirements from the v2.2.0 test is addressed:

- **CSPM:** the suppression bug is fixed and verified; CIS subset is
  documented as a subset; Azure prefix is consistent; manifest is current.
- **DevSecOps:** SARIF is the CI pick (now with fingerprints); fix is
  safe and validated (versioning patch modernized); strict defaults are
  documented (baseline on day one); supply chain stays thin (9 rules) —
  pair with Trivy/Grype, documented in the test report.
- **SOC:** attack paths work (104/105 verified); SARIF/JSON are
  SIEM-ingestible (now with compliance tags); filter to medium+ for
  alerting (documented); quality gate is 100%/100%.
- **IAM:** privesc detection and kill chains verified; duplicate rule
  removed; MFA rule added; `fix` stays detect-only by design;
  NotAction blind spot documented in code.
- **Compliance:** 10 frameworks verified; JSON/HTML audit-ready
  (single-framework JSON fixed); SARIF now carries compliance tags;
  docs refreshed to reality; SBOM deferred to v2.4.0 with a clear reason.
