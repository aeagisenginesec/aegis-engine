# Changelog

All notable changes to Aegis are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

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
  separately with documented limitations
- Rule count assertions updated across the test suite (346 total)

## Benchmarks (v1.0.0, held-out validation)

| Metric | Aegis | Checkov 3.3.26 |
|--------|------:|---------------:|
| Precision (200 held-out projects) | 0.700 | 0.700 |
| Recall | 1.000 | 1.000 |
| F1 | 0.824 | 0.824 |
| Scan speed, median (ms) | 7.8 | 4,054 |

Detection tied; Aegis ~520× faster. See `docs/PHASE5_VALIDATION.md` for
methodology, frozen versions and six documented limitations.
