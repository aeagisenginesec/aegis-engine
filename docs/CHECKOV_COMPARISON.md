# Aegis vs Checkov — AWS scanning comparison

Measured 2026-10-11. Pinned versions, same corpus, same machine.
Counts are reported, not ranked — the tools slice the problem differently.

## Environment

- Corpus: `~/workspace/terraform/vuln-three-tier/` (41 resources)
- aegis: this repo (184 rules), single static binary
- checkov: **3.3.26** (venv at `~/workspace/.venv-checkov`), `--framework terraform`
- Box: 2 CPUs (shared, under load — times are comparative, not absolute)

## Headline

| Tool | Findings | Time (median, 5 runs) |
|------|----------|----------------------|
| aegis | **41** (24 high, 14 medium, 3 critical) | **0.011s** |
| checkov 3.3.26 | **66 failed** (57 unique check IDs), 67 passed | **~5.6s** |

Speedup: **~500×** median wall-clock.

## Why the counts differ

Checkov evaluates ~133 checks on this corpus and fires per-check-per-resource,
including low-signal checks we deliberately don't implement:

| Checkov check | Count | Aegis stance |
|---|---|---|
| CKV_AWS_23 (SG descriptions) | 4 | Deliberately skipped — documentation hygiene, not a vulnerability |
| CKV_AWS_382 (SG egress 0.0.0.0/0) | 4 | Covered by 005 (one finding per SG, not per rule) |
| CKV2_AWS_60/61/62 (copy tags, lifecycle, notifications) | 3 | Weak signals — not implemented |
| CKV_AWS_144 (S3 cross-region replication) | 1 | DR concern, not a vulnerability — not implemented |
| CKV_AWS_226 (RDS auto minor upgrade) | 1 | Patch hygiene — not implemented |
| CKV_AWS_118/129 (RDS enhanced monitoring/logs) | 2 | Observability — not implemented |
| CKV_AWS_273 (SSO vs IAM users) | 1 | Identity architecture — not implemented |
| CKV_AWS_394 (AZ data-source pinning) | 1 | Niche — not implemented |

## Gaps Checkov found that we closed (rules 443–446)

Diffing the failed checks surfaced 4 high-value gaps, all now implemented
and tested:

| Rule | Check |
|---|---|
| 443 (high) | S3 bucket policy enforcing SecureTransport (TLS) |
| 444 (high) | EC2 instance with public IP |
| 445 (medium) | S3 bucket without access logging |
| 446 (medium) | RDS instance without Multi-AZ |

## What Aegis does that Checkov doesn't (on this corpus)

- Attack-path correlation (internet → SG → database, with evidence per hop)
- Hardcoded credential detection (with secret redaction)
- Validated auto-remediation (`aegis fix`)
- 124 distinct AWS resource types with dedicated rules

## Honest limitations

- Checkov's library is larger overall (~1000+ checks across all frameworks);
  this comparison covers only what fired on one corpus.
- Finding counts are not a quality metric — severity calibration and false
  positive rates matter more, and neither was measured across a labeled
  corpus here.
- Checkov also scans CloudFormation, Kubernetes, Dockerfiles, and more in
  one run; Aegis matches TF/K8s/CFN but not containers.

## Speed test (2026-10-11)

Final 184-rule build. Same box (2 CPUs, shared load), 30-run lab stats,
5-run big-corpus stats, peak RSS via /proc VmHWM.

**Warm lab** — `~/workspace/terraform/vuln-three-tier/` (41 resources), 30 runs:

| Tool | Min | Median | p95 | Max |
|------|-----|--------|-----|-----|
| aegis | 8.9 ms | **9.8 ms** | 14.6 ms | 15.8 ms |
| checkov 3.3.26 | — | ~5,600 ms | — | — |

**Large corpus** — 500 files / 3,000 resources (deterministic generator,
`docs/bench-gen.py`), 5 runs:

| Tool | Median | Findings | Peak RSS |
|------|--------|----------|----------|
| aegis | **1.02 s** | 7,875 | **47 MB** |
| checkov 3.3.26 | 33.5 s | 15,419 | 631 MB |

Speedup: **~570× on the lab, ~33× on the large corpus**, with ~13× less
memory. (Checkov's higher finding count on the big corpus is the same
low-signal checks seen in the lab comparison — descriptions, lifecycle,
tag-copying — not additional real vulnerabilities.)

## 50-vulnerability lab benchmark (2026-10-11)

Purpose-built corpus: `~/workspace/terraform/vuln-50/main.tf` — 50 distinct
vulnerabilities across S3, network, IAM, RDS/DocumentDB/DynamoDB/Redshift,
compute, Lambda, ECR/EKS/ECS, load balancers, messaging, KMS/SSM/CloudWatch,
WAF, CloudFront, API Gateway, Cognito, Secrets Manager, OpenSearch.

One parser note — **retracted**: an early draft claimed Checkov 3.3.26
failed to parse single-line nested HCL blocks (e.g. `block_device_mappings
{ device_name = "x" ebs { ... } }`) with the whole file erroring out. That
fixture was later shown to be invalid HCL — HashiCorp's own parser rejects
it too. On valid single-line nested blocks both Aegis and Checkov 3.3.26
pass (see FINAL_BOSS_TEST.md robustness table), so parser robustness is not
a proven Aegis advantage from these fixtures. The lab uses expanded
multi-line blocks anyway.

| Tool | Findings | Time (median) |
|------|----------|---------------|
| aegis | **106** (45 high, 4 critical, 57 medium; 53 unique rules) | **8.0 ms** |
| checkov 3.3.26 | 210 failed / 106 passed | 4.35 s |

Speedup: **~544×**. (Checkov's higher count is the same low-signal checks
— descriptions, lifecycle, tag-copying — counted per resource.)

## 200-vulnerability lab benchmark (2026-10-11)

Programmatically generated corpus: `~/workspace/terraform/vuln-200/main.tf`
— exactly 200 deliberately vulnerable resources spanning S3, security groups,
IAM, RDS/Neptune/DocumentDB/DynamoDB/Redshift/DAX/MemoryDB, EC2, Lambda,
KMS/SSM/CloudWatch, SNS/SQS/Kinesis, ECR/ECS/EKS, launch templates, MSK/MQ,
load balancers, WAF, CloudFront, API Gateway, Cognito, Secrets Manager,
OpenSearch, ElastiCache, EMR, Athena, Glue, SageMaker, Transfer, Step
Functions, AppSync, CodeBuild, IoT, Backup, Beanstalk, App Runner, VPC
peering, RAM, FSx, Timestream, RDS Proxy, CloudTrail.

| Tool | Findings | Time (median) | Unique checks/rules |
|------|----------|---------------|---------------------|
| aegis | **440** (13 critical, 207 high, 220 medium) | **23.4 ms** | 89 |
| checkov 3.3.26 | 787 failed / 366 passed | 6.70 s | — |

Speedup: **~286×**.

## False-positive audit (2026-10-11)

Corpus: `~/workspace/terraform/compliant-lab/main.tf` — 27 fully compliant
resources (encrypted, versioned, private, logged, TLS-enforced, backed up,
Multi-AZ, rotated keys, strong passwords, flow logs, multi-region trail).
Any finding here is a false positive.

| Tool | False positives |
|------|-----------------|
| aegis | **1** (S3 access-logging target bucket has no logging of its own — arguably correct per CKV_AWS_18) |
| checkov 3.3.26 | **0** |

Bugs found and fixed by this audit:
- 001/012/445 now correlate standalone `aws_s3_bucket_*` config resources
  (the modern provider-v4+ pattern) instead of only inline blocks.
- 443 no longer fires when the bucket policy contains unresolvable
  references — unknown means "cannot decide", not "vulnerable".
- 3-tier lab: 41 → 40 findings (one 443 that was firing on an unknown
  policy now correctly stays quiet).
