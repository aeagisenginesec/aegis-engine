# Changelog

All notable changes to Aegis are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [2.4.0] — 2026-11-25

### Added

- **SBOM generation for scanned projects (`--sbom`).**
  `aegis scan --sbom spdx-json|cyclonedx-json <dir>` writes a dependency
  inventory alongside the findings report: SPDX 2.3 JSON (primary) or
  CycloneDX 1.6 JSON. Covers Terraform `required_providers` + module
  sources (with versions where pinned), Dockerfile base images, and
  Compose service images — direct references only, no transitive
  resolution, no lock-file or registry lookups (see `docs/SBOM.md`).
  Default outputs `sbom.spdx.json` / `sbom.cyclonedx.json` are skipped
  by discovery on later scans.
- **NotAction / NotResource policy-evaluation semantics (IAM #4, v2.4.0).**
  The IAM pack no longer silently skips statements using `NotAction` /
  `NotResource` ("cannot decide -> silent"). A new shared evaluator
  (`internal/rules/aws/iam_policy_eval.go`) gives every IAM rule real
  policy-evaluation semantics: a `NotAction` statement grants every
  action its exclusion list does not cover, and a `NotResource` statement
  grants on every resource its exclusion list does not cover. A broad
  grant such as `NotAction: ["iam:DeleteUser"]` on `*` is now treated as
  the near-admin grant it is, and findings carry the exclusion in their
  evidence so a finding never claims a resource the policy explicitly
  excludes. Rules now evaluating negative logic: 006, 101, 102, 333,
  501–505, 660, 661, 670, 676, 859, and the 104 attack-path public-read
  link. No new rules: 553 and 671 still flag the `NotAction` /
  `NotResource` constructs themselves. Deliberate limits: coverage is
  tested per exclusion pattern (not over the list's union); explicit
  Deny interaction is still out of scope; `?` wildcards are literals.
  One golden updated for the intended behavior change: 661 now fires on
  the `iam-wildcard/vuln` parity fixture (Action `*` grants
  `iam:PassRole` on `*`, as 502 already treated it), 8 → 9 findings on
  all five adapters.

## [2.3.0] — 2026-11-24

The five-agent test release. All five cloud-engineer specialist agents
(ObsidianX-CSPM, ObsidianX-DevSecOps, ObsidianX-SOC, ObsidianX-IAM,
ObsidianX-Compliance) ran a complex test of v2.2.0 and every finding in
this release answers one of their requirements. Rule count stays 1,140
(net zero: one duplicate removed, one new rule added).

### Fixed

- **Cross-file address-collision suppression (false negatives).**
  `linkedBucketAddr` / `linkedTargetBucketAddr` now return no link when
  a bucket reference is ambiguous (the same resource address defined in
  multiple files in one directory). Previously a public bucket policy in
  one file silently suppressed S3 encryption (001) and public-access-block
  (206) findings on a different bucket sharing the address. Legitimate
  cross-file correlation inside a real module (unique addresses) is
  unaffected. Fail-safe: ambiguous links suppress nothing.
- **Duplicate IAM rule removed: AEGIS-AWS-668.** The access-key PGP
  issue was flagged twice (552 High, 668 Low). Kept 552 (correct
  severity, dedicated unit tests, remediation entry); ported 668's
  better description wording into 552 and fixed 552's remediation text
  (it wrongly described key rotation instead of `pgp_key`).
- **Azure rule-prefix inconsistency.** `AEGIS-AZR-001/002/003/005`
  renamed to `AEGIS-AZURE-001/002/003/005`; all 277 Azure rules now use
  the single `AEGIS-AZURE-` prefix. (`AEGIS-AZR-004` remains only as a
  deprecated-mapping pointer pinned by migration tests.)
- **Single-framework JSON omitted the posture summary.**
  `--compliance=CIS-AWS-1.5 --format=json` returned
  `compliance_summaries: null`; it now returns a one-element array,
  the same shape as `--compliance=all`.
- **`aegis fix` S3 versioning patch used deprecated syntax.** The
  versioning fixer now proposes a separate `aws_s3_bucket_versioning`
  resource instead of the inline `versioning {}` block (deprecated in
  AWS provider v4+). Guards against duplicating an existing versioning
  resource; CRLF files handled.
- **`aegis scan` required a directory.** Single files are now accepted
  (`aegis scan main.tf`); `fix` still requires a directory. Symlinks
  and non-regular files are rejected; nonexistent targets error cleanly.
- **Scan outputs were parsed as manifests.** `out.json`, `out.sarif`,
  `out.html`, `aegis.json`, `aegis.sarif` are now skipped when collecting
  scan targets below the scan root (an explicitly named file is still
  scanned).

### Added

- **New IAM rule AEGIS-AWS-859 (Medium): admin access without MFA
  condition.** Fires on an open trust (`Principal "*"`) or an admin
  policy (`Action "*"` / `iam:*`) with no Condition requiring
  `aws:MultiFactorAuthAge` or `aws:MultiFactorAuthPresent`. A Condition
  on anything else does not satisfy it.
- **SARIF compliance tags.** Results and rule metadata now carry
  `properties.tags` with `Framework:Control` entries (e.g.
  `CIS-AWS-1.5:2.1.1`, `NIST-800-53:AC-4`) for every finding that has
  compliance mappings.
- **SARIF partialFingerprints.** Every result carries a stable SHA-256
  fingerprint (`aegis/v1`, from rule + resource + file + line) for
  GitHub code scanning dedup.

### Changed

- **Benchmark manifest updated.** Scenario 07 now expects
  `AEGIS-AWS-604` (rule 005 deliberately fires only on security groups
  attached to a workload); scenario 10 now expects `AEGIS-AWS-666`
  (AWS-managed `AdministratorAccess` attachments). The secure 07
  fixture now carries a `description` on the security group and its
  egress rule, so 604 stays silent there and the scenario
  discriminates. All 34 scenarios match, 0 mismatches.
- **Docs refreshed.** `docs/COMPLIANCE.md` rewritten (10 frameworks,
  943/1,140 rules mapped); `docs/COVERAGE_MATRIX.md` updated to the
  1,140-rule inventory and marked current for v2.3.0.
- **NotAction/NotResource blind spot documented in code.** The shared
  policy parser now notes that statements using `NotAction` /
  `NotResource` are skipped ("cannot decide → silent") — a deliberate
  soundness trade-off, not proof of safety.

### Notes

- Rule count is unchanged at 1,140 (668 out, 859 in). Quality gate:
  precision 100%, recall 100%, rule-coverage 355/355.
- CIS coverage remains a subset by design (12/60 AWS controls) — the
  posture report covers the mapped controls, not the full benchmark.
- `compliance_summary` (singular) is no longer populated by the CLI in
  single-framework mode; read `compliance_summaries[0]` instead.

## [2.2.0] — 2026-10-22

The compliance & governance release. Detection is unchanged (the same
1,140 rules; quality gate precision/recall 100% on the locked corpora) —
what changes is how completely findings speak the language of audits, and
how accepted risk is governed.

### Added

- **Compliance coverage 240 → 943 rules (of 1,140).** Every provider pack
  is now mapped — Azure (277 rules) and the Kubernetes/Docker/Compose/
  Alibaba/OCI packs included. 197 rules remain deliberately unmapped where
  no control genuinely applies; the doctrine (map only what truly fits)
  is unchanged.
- **Seven new frameworks**: CIS-Azure-2.1, CIS-GCP-1.3,
  CIS-Kubernetes-1.8, CIS-Docker-1.6, ISO-27001-2022, SOC 2 and HIPAA —
  ten in total. ISO/SOC 2/HIPAA references are crosswalked from each
  rule's NIST 800-53 anchors.
- **Multi-framework posture**: `--compliance` accepts a comma-separated
  list or `all`, reporting one per-control pass/fail summary per
  framework (text and JSON `compliance_summaries`). A single framework
  keeps the original filter-and-summarize behaviour.
- **HTML attestation report**: `--format=html` renders a standalone,
  deterministic, secret-redacted attestation page (posture table for all
  frameworks + full findings table).
- **Waivers with visible expiry**: `--waiver-reason/--waiver-owner/
  --waiver-expires` author expiring baseline waivers from the CLI. A
  lapsed waiver reinstates its finding and warns on stderr (date, rule,
  resource, owner); an unparseable expiry is flagged on every load
  instead of silently becoming permanent.

### Notes

- CIS controls are cited only where the benchmark control is certain —
  precision over coverage, as with the original map.
- Posture means "no mapped finding fired in this tree": evidence for an
  audit, not the audit itself. See docs/compliance.md.

## [2.1.1] — 2026-10-21

Security-maintenance and CI/CD release. No rule changes: the detection
engine is byte-for-byte the v2.1.0 closeout build (full test suite and
the R4 regression locks green on the new toolchain).

### Security

- **Go 1.25 → 1.26**: govulncheck against the old toolchain reported
  25 reachable vulnerabilities (24 in the standard library — the
  `aegis serve` HTTP surface reaches crypto/x509 and net/http — plus
  golang.org/x/text v0.31.0). On Go 1.26.10 with the bumped module
  graph (x/text v0.43.0 et al.): **no vulnerabilities found**.
- **Pulumi adapter**: malformed `!!int`/`!!float` scalars now yield
  Unknown values instead of a silent known-zero.

### CI/CD (the full suite)

- **Lint gate** (golangci-lint): errcheck/govet/ineffassign/
  staticcheck/unused at zero findings, reached by fixing the code —
  19 dead functions removed, dead initializers and De Morgan cleanups,
  and one placeholder test assertion made real. Remaining exceptions
  are named and justified in `.golangci.yml`.
- **Security workflow**: CodeQL analysis + govulncheck as a hard gate
  (tracking the newest Go patch — a bare `go 1.26.0` pin fails with
  the stdlib vulns fixed in 1.26.1+). Weekly scheduled re-scans.
- **Aegis self-gate** now actually fires (its push trigger pointed at
  a `main` branch this repo never had) and judges new findings only,
  via `.aegis/baseline.json` generated from the tracked tree.
- **Container image**: multi-arch (amd64/arm64) GHCR image published
  on every release (`ghcr.io/aeagisenginesec/aegis-engine`).
- **Dependabot**: weekly Go-module and Actions updates.
- Private-repo adaptation: GitHub code scanning requires Advanced
  Security on private repos, so CodeQL/gate SARIF is archived as run
  artifacts (documented in both workflows, one-line restore).

## [2.1.0] — 2026-10-21

Accuracy closeout release: the R4 ground truth is fully solved (zero
false negatives, zero false positives), the false-positive families
found by a 2,227-candidate adjudication are eliminated, and a blind
210-project evaluation (R5) is published with an honest verdict. Rule
registry: 1,140 active rules. Full record: `docs/audit/24_FP_FN_ELIMINATION_PLAN.md`,
`docs/audit/25_FP_FAMILY_KILL.md`, `docs/audit/26_AEGIS_FINAL_STATE.md`.

### Added

- **AEGIS-AWS-858**: security group open to the world on database ports
  (1433/1521/3306/5432/5984/6379/9200/27017), across all SG resource forms.
- **AEGIS-COMPOSE-009**: Docker Compose `network_mode: host`.

### Fixed — accuracy

- **R4 false negatives 8 → 0** (TP 136/136, recall 1.000): the two rules
  above, an ARM template-map casing bug that hid AKS `enableRBAC: false`
  (AZURE-014), and regression locks for Cosmos public network access.
- **False-positive families killed**: 15 duplicate rules deprecated
  (each mapped to its surviving canonical rule), DOCKER-017/018 gated to
  final build stages (20 false positives on discarded stages), AWS-311
  scoped to known database engines.
- **ARM/Bicep correctness**: storage-account rule translations that were
  unreachable are now wired; a VNet DDoS attribute collision that made
  scans nondeterministic (~1 in 5 runs) is merged deterministically.

### Fixed — engine

- **Discovery readability probe**: files discovery cannot open are now
  skipped during the walk and recorded in the Skipped report with a
  reason, instead of surfacing later as parse failures. Caught by the
  first GitHub CI run of the closeout branch; verified as a non-root user.

### Performance

- S3 correlation pass is O(1) per bucket (was O(R²)): the 100k-line
  fixture scans in ~5.4s (was 38.2s); 1,003,677 findings on the
  1.7M-line fixture in ~2 minutes.

## [2.0.0] — 2026-10-14

Second stable release. 1,153 detection rules (1,152 active) across AWS,
Azure, GCP, Alibaba, OCI, Kubernetes, Docker, Compose, supply-chain and
Terraform packs. Top-tier validation complete: R4 blind evaluation
(F1 0.950 vs Checkov 0.331, KICS 0.371, Trivy 0.279 on a frozen 136-concept
ground truth), multi-cloud finding quality audit, and a Pulumi
honest-reporting guarantee. See `docs/audit/16_RELEASE_NOTES_v2.0.0.md`.

### Added

- **K8s hardening rules K8S-028..032**: read-only root filesystem, seccomp
  profile, drop ALL capabilities, NetworkPolicy coverage, image digest pin.
- **AWS-856**: EC2 end-of-life OS image (mirrors GCP-294), with 22
  positive/negative tests.
- **GCP-293/GCP-294**: startup-script secret detection and Debian/Ubuntu
  EOL boot-disk image detection.
- **AWS-534**: secret exposure in EC2 `user_data` (literal secrets →
  Critical, `${var.<secret-like>}` taint → High).
- **AWS-005** (SG egress), **AWS-538** (plaintext variable default),
  **AWS-710** (RDS Secrets Manager), **GCP-040** (SQL authorized_networks),
  **GCP-068** (firewall all-ports): true-positive gaps found by the
  multi-cloud audit, now covered.
- **Pulumi honest warnings**: TypeScript/JavaScript, Python, Go, .NET and
  Java programs are detected (via `runtime:` or language markers) and emit
  a warning naming the unparsed program files — no Pulumi language ever
  scans silently as "0 findings".
- **Unknown/deprecated rule-ID diagnostics** for baselines and inline
  suppressions.
- **CI/CD workflows**: GitHub Actions PR gate + GitLab CI (`aegis-scan.yml`,
  `aegis.yml`); release build/test/quality-gate workflow (`ci.yml`).
- **Azure SQL coverage**: weak admin password (314), legacy auditing.
- **Round-3 gap-closure rules**: AWS-850, CloudFormation Lambda URL,
  DOCKER-036, K8S-026/027.

### Changed

- **Rule count 346 → 1,153** (registry-verified; 1,152 active + 1 deprecated).
- **R4 F1 0.921 → 0.950** (precision 1.000, recall 0.904): CloudFormation
  duplicate-key parser fix, 6 new rules (AWS-851..855, DOCKER-037),
  compliant-lab factual fixes.
- **Held-out benchmark F1 0.824 → 1.000**: 60 false positives on hardened
  clean projects eliminated, recall held at 100%.
- **GCP-122 deprecated** in favor of canonical GCP-032 (identical
  public-access-prevention condition).
- **Span exactness**: parser repair now remaps repaired→original lines so
  findings cite exact file/line.
- **Cloud-aware remediation**: non-AWS findings no longer served AWS-specific
  fix text; 15 remediation mismatches corrected.
- **HCL parser leniency** (`internal/adapter/terraform`): single-line object
  constructors without comma separators no longer silently mangle
  `jsonencode()` policy documents; commas inserted at exact diagnostic
  positions with iterative re-parse.
- **AWS-209 scoped to VPCs with subnets**; **AWS-005 egress gated on
  attachment evidence**; **DOCKER-002 scoped to final stages**,
  first-party registries trusted in DOCKER-010; S3 SSE/PAB suppressed on
  intentionally-public buckets; log-delivery buckets exempt from S3
  hardening findings.
- **Scale/reliability**: per-parser fuzz hardening, alias-cycle protection,
  memoization, multi-document manifests, Terraform recovery.

### Fixed

- **9 duplicate rules removed** (8 Azure SQL + 1 GCP scope); **1
  parser-artifact false firing removed** (GCP-214, fired only because the
  parser dropped the `ports` attribute).
- **7 false positives**: GCP-101..107 (PostgreSQL flags firing on MySQL)
  now engine-gated via `sqlIsPostgres()`.
- **AZR-002 TLS FP**: now accepts TLS1_2/TLS1_3 like sibling rules.
- **Terraform parser dropping attributes after the first on a line**;
  `jsonencode`/`merge`/`concat` evaluated over static arguments.
- **Pulumi adapter**: template:-nested layout, Azure storage property
  normalization, typemap entries, nested-properties gaps.
- **Module duplicate findings** (bare twins).
- **GCP-017**: forwarding appliances exempt from public-IP findings.
- **AWS-607** attribute-name bug; **AZURE-033** dead rule revived.

### Removed

- **4 S3 hygiene rules** (AEGIS-AWS-558 Object Lock, 559 inventory, 602
  event notifications, 603 cross-region replication): flagged every bucket
  including fully-hardened ones — operational recommendations, not
  vulnerabilities. 240 false positives on the held-out set, zero unique
  true positives.

## [1.0.0] — 2026-10-11

First stable release. 346 detection rules across AWS, Azure, GCP, Kubernetes,
Docker, supply-chain and Terraform packs. Five engineering phases complete:
quality gates, coverage matrix, attack-path analysis, production hardening,
and independent held-out validation.

### Added

- **346 detection rules** (245 AWS, 25 Azure, 24 GCP, 10 Docker, 3 Kubernetes,
  9 supply-chain, 8 Terraform):
  - AEGIS-AWS-501–533: IAM privilege escalation, network exposure, encryption
    gaps, authentication and supply-chain hardening
  - AEGIS-AWS-534–539: secrets in EC2 user data, provisioner passwords, unsafe
    outputs, secrets in tags/variables/locals (values redacted)
  - AEGIS-AWS-540–544, 546–551: RDS IAM auth, launch-config IMDSv1, Lambda VPC
    placement, ElastiCache encryption and availability
  - AEGIS-AWS-552–571: top-20 coverage-matrix gaps — IAM key rotation,
    NotAction deny-bypass, Transit Gateway propagation, S3 Object Lock, KMS
    deletion windows, Secrets Manager CMK, Security Hub, Detective,
    CodeArtifact upstream restrictions
  - AEGIS-AWS-601–626: low-severity hygiene rules
  - AEGIS-AWS-629: full kill-chain detection (internet → entry → workload →
    IAM role → data store) with per-hop evidence
  - AEGIS-AWS-630: IAM privilege chains (role → policy → workload)
  - AEGIS-TF-001–008: Terraform backend encryption/locking, version pinning,
    provider credential validation
  - AEGIS-SC-002–009: public ECR images, curl|bash, unpinned AMIs, remote exec
- **`aegis quality-gate`**: automated release-blocking test suite — precision
  ≥95%, recall ≥90%, rule-coverage, performance p95 ≤500ms, parser safety
- **`aegis doctor`**: binary self-check (registry, parser, engine, remediation
  dry-run); exits 0 when healthy
- **`aegis scan --attack-paths`**: renders evidence-backed kill chains as ASCII
  diagrams and full-evidence JSON; explicit `[UNCERTAIN]` markers when
  variables or dynamic blocks prevent conclusions
- **Secret taint tracking**: secrets detected in user data, tags, outputs and
  variable defaults with values redacted in all output
- **Multi-hop AWS attack paths** via the resource relationship graph
- **CIS AWS 1.5, NIST 800-53 and PCI DSS** control mappings
- **Inline suppressions** (`# aegis:ignore=RULE-ID`) and stable baseline files
- **YAML custom rules** for user-defined checks
- **SARIF, JSON and text** output formats
- **Production-safe remediation** (`aegis fix`): dry-run by default, minimal
  diffs, re-parse validation, regression re-check; IAM and security-group
  resources blocked without `--force`
- **Parser hardening**: explicit errors for null bytes, UTF-16, >10MB files,
  >50 nesting levels, truncated input — never silently treated as clean;
  Go fuzzing seed corpus (`FuzzParseModule`)
- **Regression suite**: golden-file snapshots; any rule-output change fails
  loudly until explicitly reviewed
- **`--max-file-size` and `--timeout`** scan flags for large repositories
- Version stamping: `aegis --version`, `aegis_version` in JSON/SARIF envelopes

### Fixed

- Removed duplicate rule AEGIS-AWS-545 (overlapped AEGIS-AWS-446)
- Fixed ID-ordering in the AWS rule registry
- SG ingress parsing: nested `ingress[]` → `cidr_blocks[]` blocks (was read
  as flat attributes)
- `vpc_security_group_ids` with references now resolved via `Ref` fields
- JSON policy parsing is defensive: unparseable policies produce no finding,
  never panic

### Changed

- `docs/FINAL_VERDICT.md` rewritten with rigorous per-metric reporting —
  removed unconditional "winner" claims; reports precision/recall/F1/speed
  separately
- Rule count assertions updated across the test suite (346 total)

## Benchmarks (v1.0.0, held-out validation)

| Metric | Aegis | Checkov 3.3.26 |
|--------|------:|---------------:|
| Precision (200 held-out projects) | 0.700 | 0.700 |
| Recall | 1.000 | 1.000 |
| F1 | 0.824 | 0.824 |
| Scan speed, median (ms) | 7.8 | 4,054 |

Detection tied; Aegis ~520× faster. See `docs/PHASE5_VALIDATION.md` for
methodology and frozen versions.
