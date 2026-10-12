# Aegis v1.0.0 — Release Record

**Release:** v1.0.0 (production)
**Date:** 2026-10-12
**Status:** LOCAL release — not published to GitHub. Distribution via `~/workspace/your_files/aegis-engine.zip`.

## Provenance

| Item | Value |
|------|-------|
| Git tag | `v1.0.0` (annotated, **unsigned** — no GPG key in sandbox) |
| Release commit | `35d5858c5c41eaff42b734326d978572f8545d1d` |
| Branch state | Working tree clean at tag time |
| Toolchain | Go 1.25.4 linux/amd64 |
| Build flags | `CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w"` |
| Binary | `aegis-v1.0.0` (Linux AMD64, 12 MB) |

### Binary SHA-256

```
5ab082fca08a2d3c0b41f06f6cc6435f5d9a09c47f4f4f4b0050f3dc1a23f66b  aegis-v1.0.0
```

**Reproducibility:** Two independent builds from the tagged commit with the flags above produced bit-identical SHA-256 hashes. Note: default `go build` embeds VCS stamping (commit hash), which breaks bit-reproducibility; `-buildvcs=false` was used for the release binary. Trade-off documented: the release binary does not self-report its commit hash (`--version` shows "commit unknown"); the commit is recorded here instead.

## Test Results (all green at release)

| Check | Result |
|-------|--------|
| `go test ./...` | All 22 packages PASS |
| `go vet ./...` | Clean |
| `gofmt -l .` | Clean |
| `go test -race` (rules, remediation, semantics) | Clean, zero data races |
| `aegis quality-gate` | **PASS** (5/5) |
| Precision (medium+) | 100.0% (tp=355, fp=0, fn=0) |
| Recall (medium+) | 100.0% |
| Rule coverage | 216/216 critical/high rules tested |
| Performance | median 18.8 ms, p95 27.8 ms (threshold p95 ≤ 500 ms) |
| Parser safety | 15/15 malformed inputs produce explicit diagnostics |
| Labeled corpus (100 projects) | Precision 1.000, Recall 1.000, F1 1.000 |

## Post-Build Verification (using release binary)

| Check | Result |
|-------|--------|
| `--version` | `aegis 1.0.0` ✅ |
| `doctor` | 587 rules loaded ✅ |
| vuln-22 scan | 105 findings (matches expected) ✅ |
| SARIF output | Valid 2.1.0, 105 results ✅ |
| JSON output | Valid, 105 findings ✅ |
| Exit codes | 0 = below `--fail-on`, 1 = at/above threshold, 2 = scan error ✅ |

## SBOM

`SBOM.md` — 24 Go module dependencies, all permissively licensed (MIT, BSD-3, Apache-2.0, MPL-2.0). **No GPL/AGPL.** No known-vulnerability scan was possible in the sandbox (`govulncheck` module resolution failure); manual review found no network-facing or crypto libraries beyond Go stdlib.

## Security Review

- **Secrets scan:** No real credentials in source. Two benign hits: a comment describing secret-detection regex patterns, and a remediation code template. Test fixtures use `<redacted>` placeholders.
- **Threat model:** `docs/THREAT_MODEL.md`
- **Known limitations:** `docs/LIMITATIONS.md` (honest gaps: Azure/GCP thin vs AWS, no CloudFormation, hygiene noise)

## Documentation Included

- `README.md` — installation, usage
- `docs/THREAT_MODEL.md`, `docs/LIMITATIONS.md`, `docs/ARCHITECTURE.md`
- `docs/CI_INTEGRATION.md` — GitHub Actions, GitLab CI, pre-commit, Jenkins
- `docs/BASELINES.md` — suppression with reason/owner/expiry
- `docs/DETECTION_CORRECTNESS.md`, `docs/ENGINE_HARDENING.md`
- `docs/PERFORMANCE_OPTIMIZATION.md`, `docs/PERFORMANCE_REGRESSION.md`
- `docs/REMEDIATION_SAFETY.md`, `docs/FOLLOWUP_FIXES.md`
- `docs/RELEASE_CHECKLIST.md`

## Known Gaps (not done)

1. **No GPG signing** — tag is annotated but unsigned; binaries unsigned. Requires a GPG key at publish time.
2. **No GitHub remote** — repository is local-only. Push and GitHub Release creation are Reda's decision.
3. **`govulncheck` could not run** — documented in SBOM.md; recommend running in CI.
4. **No multi-platform builds** — Linux AMD64 only. Windows/macOS builds not produced.

## Controlled Rollout Plan

v1.0.0 should be treated as the **beginning of evidence-driven maintenance**, not the end of development:

1. **Report-only mode** — Run Aegis against representative AWS repositories without auto-remediation. Do not enable `--apply` in production until fixes are reviewed.
2. **Collect feedback** — False positives, missed findings, parser failures, performance regressions. File each as an issue.
3. **Regression tests** — Every material defect gets a regression fixture before the fix lands.
4. **Patch process** — v1.0.1, v1.0.2 for fixes. No feature additions in patch releases.
5. **Remediation safety** — Automatic remediation stays dry-run by default. IAM/networking changes require `--force` and human review.

The next milestone is **feedback from real AWS projects**, with every defect converted into a regression test.
