# Changelog

All notable changes to Aegis are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Fixed

- **Held-out benchmark F1 0.824 → 1.000** (beats Checkov 0.824): 60 false
  positives on hardened clean projects eliminated, recall held at 100%.
- **HCL parser leniency** (`internal/adapter/terraform`): single-line object
  constructors without comma separators (`{ Effect = "Allow" Action = ... }`)
  no longer silently mangle `jsonencode()` policy documents. On "Missing
  attribute separator" diagnostics, commas are inserted at the exact diagnostic
  positions and the source is re-parsed (iterative); falls back to the original
  partial result if recovery fails. This un-breaks AEGIS-AWS-502 (and other
  policy rules) on such inputs — 8 held-out `iam-escalation` projects are now
  genuinely detected instead of incidentally via the dummy VPC.
- **Log-delivery bucket exemption** (AEGIS-AWS-001/012/206/443/601, shared
  `logDeliveryBuckets` helper): buckets that are `target_bucket` of an
  `aws_s3_bucket_logging` resource are logging infrastructure and no longer
  flagged for missing hardening. Extends the AEGIS-AWS-445 precedent.
- **AEGIS-AWS-209 scoped to VPCs with subnets**: a VPC with no subnets carries
  no traffic; flow logs would capture nothing. Fail-safe: unresolvable subnet
  `vpc_id` still flags.

### Removed

- **4 S3 hygiene rules** (AEGIS-AWS-558 Object Lock, 559 inventory, 602 event
  notifications, 603 cross-region replication): flagged every bucket including
  fully-hardened ones — operational recommendations, not vulnerabilities.
  240 false positives on the held-out set, zero unique true positives.

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
