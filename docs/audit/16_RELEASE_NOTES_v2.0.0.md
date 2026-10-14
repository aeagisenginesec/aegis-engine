# Aegis v2.0.0 — Release Notes

**Date:** 2026-10-14 · **Commit:** `d22d385` (tag `v2.0.0`, local only — not pushed)
**Branch:** `mission/gap-userdata-eol-image`

Second stable release. All numbers below were verified on the release tree
on 2026-10-14; nothing here is projected or estimated.

## What's in v2.0.0

- **1,153 detection rules** (registry-verified; 1,152 active + 1 deprecated)
  across AWS, Azure, GCP, Alibaba, OCI, Kubernetes, Docker, Compose,
  supply-chain and Terraform packs.
- **Top-tier validation complete**: R4 blind evaluation on a frozen
  136-concept ground truth — Aegis F1 **0.950** (precision 1.000, recall
  0.904) vs Checkov 0.331, KICS 0.371, Trivy 0.279; 2.2 s vs 324.9 s sweep
  time. See `docs/audit/14_TRIVY_OUTPERFORM_REPORT.md`.
- **Multi-cloud finding quality audit** (`docs/audit/15_MULTICLOUD_QUALITY_AUDIT.md`,
  §16): 133 → 122 findings on the multi-cloud Terraform fixture. 8
  true-positive misses fixed (incl. EC2 `user_data` secret → AWS-534 and
  Debian 10 EOL image → GCP-294), 9 duplicate rules removed, 7 false
  positives fixed (GCP-101..107 on MySQL), 15 remediation texts corrected,
  parser diagnostics 13 → 0.
- **K8s hardening rules K8S-028..032**: read-only root filesystem, seccomp
  profile, drop ALL capabilities, NetworkPolicy coverage, image digest pin.
- **AWS-856**: EC2 end-of-life OS image (High), with 22 pos/neg tests.
- **Pulumi honest reporting**: TypeScript/JavaScript, Python, Go, .NET and
  Java programs are *detected but not analyzed* — the scanner emits a
  warning naming the unparsed program files instead of a silent "0
  findings". Pulumi YAML is analyzed declaratively.
- **Deterministic**: identical input → byte-identical JSON, verified 5/5.
- **Release engineering**: version constant (`aegis --version` →
  `aegis 2.0.0`), CHANGELOG, CycloneDX SBOM, release CI workflow,
  signed-by-checksum multi-platform binaries.

## Verified numbers (2026-10-14, release tree)

| Check | Result |
|---|---|
| `go test ./...` | **green** — 32 packages, 0 FAIL |
| `go test -race` (touched packages) | clean |
| `aegis quality-gate` | **5/5 PASS** — precision 100.0% (355/355), recall 100.0%, rule-coverage 357/357, perf p95 65.4 ms (≤500 ms), parser-safety 15/15 |
| Determinism (multi-cloud fixture, 5 runs) | byte-identical 5/5 |
| Multi-cloud fixture | **122 findings** (5 critical / 39 high / 46 medium / 32 low), 0.04 s wall, ~19.8 MB peak RSS |
| Ultimate 6-format fixture | **155 findings** (was 163 pre-audit; the −8 delta is exactly the 8 removed Azure-SQL duplicate rules, verified by before/after diff), 0.04 s, ~20.7 MB |
| `aegis --version` | `aegis 2.0.0 (build 2026-10-14, commit d22d385)` |

Binaries (in the release bundle, SHA256 in `SHA256SUMS`):

| Binary | Size |
|---|---|
| `aegis-v2.0.0-linux-amd64` | ~15.8 MB |
| `aegis-v2.0.0-darwin-arm64` | ~15.4 MB |
| `aegis-v2.0.0-windows-amd64.exe` | ~16.1 MB |

## Known limitations (honest)

- **Scope is IaC misconfiguration only.** Aegis is not a CVE scanner and
  does not scan container images, SBOMs, licenses, or live cloud accounts.
  All benchmark claims (R4 F1, speed) are measured on IaC-misconfiguration
  workloads against the frozen 136-concept ground truth — not "all
  scanning".
- **Pulumi imperative languages are detected, not analyzed.**
  TypeScript/JavaScript, Python, Go, .NET and Java programs produce a
  warning, not findings. Heuristic extraction or a full parser is future
  work.
- **EOL OS tables are static** (AWS-856, GCP-294) and need maintenance as
  distributions reach end-of-life.
- **GCP-293** misses secret interpolations inside metadata *maps*.
- **AWS-103** (public RDS exposure path) assumes a subnet layout the
  fixture does not declare; the assumption is unstated in the finding.
- **TF-003** (unpinned providers) severity wording was flagged but not
  changed.
- **K8s remediation texts** were spot-checked, not exhaustively audited.
- **Parser repair is bounded**: heavily malformed inputs fall back to the
  partial parse with diagnostics rather than failing.
- **CI workflow** (`.github/workflows/ci.yml`) is authored but has never
  run against GitHub — the repository does not exist yet.
- **122 findings are unadjudicated raw counts**, not precision evidence.

## Upgrade notes

- `aegis --version` now reports `2.0.0`. The `version.BuildDate` and
  `version.Commit` fields are stamped via `-ldflags` at build time
  (see `internal/version/version.go`).
- Two `cmd/aegis` tests were converted from hardcoded version strings to
  the `version.Version` constant, so future bumps don't break them.
- `.gitignore`: the `aegis` pattern is now root-anchored (`/aegis`) so it
  no longer matches the `cmd/aegis/` source directory.
- GCP-122 is deprecated in favor of GCP-032 (use the canonical ID in
  baselines and suppressions; `DEPRECATED_RULE_IDS.md` maps it).
