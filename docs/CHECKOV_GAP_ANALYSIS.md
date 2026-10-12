# Checkov vs Aegis — AWS Detection Gap Analysis

**Date:** 2026-10-11
**Checkov:** 3.3.26 | **Aegis:** 235 rules (172 AWS)
**Corpus:** `~/workspace/terraform/vuln-200/` (200 resources)

## Executive Summary

Checkov reports **787 failures** vs Aegis's **451 findings** on the same corpus.
But the raw count is misleading. Here's where Checkov's lead actually comes from:

| Category | Unique Checks | Failures | % of Failures | What It Means |
|----------|--------------|----------|---------------|---------------|
| **Already Covered** | 88 | 394 | 50.1% | Aegis has equivalent rules |
| **Hygiene/Availability** | 35 | 221 | 28.1% | Logging, lifecycle, tagging — not security-critical |
| **Real Security Gaps** | 33 | 79 | 10.0% | Genuine vulnerabilities Aegis misses |
| **False Positives** | 12 | 59 | 7.5% | Checkov fires on the compliant fixture |
| **Duplicates** | 12 | 34 | 4.3% | Stricter KMS-CMK variants of rules Aegis has |

**Bottom line:** Only **10% of Checkov's findings** represent real security gaps.
Half are already covered by Aegis. Over a third are hygiene or noise.

## Methodology

1. Ran Checkov 3.3.26 on vuln-200 with JSON output → 787 failures, 180 unique check IDs
2. Ran Checkov on `~/workspace/terraform/compliant-lab/` → 27 failures, 24 unique IDs (noise baseline)
3. Mapped each of the 180 Checkov checks against Aegis's 172 AWS rules by reading rule implementations
4. Categorized as: COVERED / GAP / HYGIENE / DUPLICATE / NOISE

## Prioritized Real Security Gaps

33 checks Aegis should implement. Suggested IDs: **AEGIS-AWS-501+**.
Ranked by severity × prevalence × distinctiveness.

### Tier 1: Critical IAM Privilege Analysis (5 checks, 15 failures)

These are Checkov's most sophisticated checks — they analyze IAM policy
semantics for privilege escalation paths, not just blanket `*` permissions.

| # | Checkov ID | What It Detects | Suggested Aegis ID | Severity |
|---|-----------|-----------------|-------------------|----------|
| 1 | CKV_AWS_286 | IAM privilege escalation (e.g., `iam:CreatePolicy` + `iam:AttachRolePolicy`) | AEGIS-AWS-501 | Critical |
| 2 | CKV_AWS_287 | Credential exposure (`iam:PassRole` + `ec2:RunInstances`, `lambda:CreateFunction`) | AEGIS-AWS-502 | Critical |
| 3 | CKV_AWS_288 | Data exfiltration (`s3:GetObject` + `s3:PutObject` on `*`, `rds:CreateDBSnapshot` + share) | AEGIS-AWS-503 | High |
| 4 | CKV_AWS_289 | Permissions management without constraints (`iam:*` scoped but dangerous) | AEGIS-AWS-504 | High |
| 5 | CKV_AWS_290 | Write access without resource constraints | AEGIS-AWS-505 | High |

**Why Tier 1:** These catch real attack paths that AEGIS-AWS-006 (blanket admin check)
misses. A policy allowing `iam:PassRole` on `*` + `ec2:RunInstances` is a textbook
privilege escalation that Aegis currently cannot detect.

### Tier 2: Network Exposure & Access Control (8 checks, 17 failures)

| # | Checkov ID | What It Detects | Suggested Aegis ID | Severity |
|---|-----------|-----------------|-------------------|----------|
| 6 | CKV2_AWS_28 | Public ALB without WAF protection | AEGIS-AWS-506 | High |
| 7 | CKV_AWS_137 | Elasticsearch/OpenSearch outside VPC | AEGIS-AWS-507 | High |
| 8 | CKV_AWS_154 | Redshift cluster outside VPC | AEGIS-AWS-508 | High |
| 9 | CKV_AWS_164 | Transfer Server publicly accessible | AEGIS-AWS-509 | High |
| 10 | CKV2_AWS_20 | ALB without HTTP→HTTPS redirect | AEGIS-AWS-510 | Medium |
| 11 | CKV_AWS_306 | SageMaker notebook not in custom VPC | AEGIS-AWS-511 | Medium |
| 12 | CKV_AWS_374 | CloudFront without geo restriction | AEGIS-AWS-512 | Medium |
| 13 | CKV2_AWS_33 | AppSync API without WAF protection | AEGIS-AWS-513 | Medium |

### Tier 3: Encryption Gaps (7 checks, 16 failures)

| # | Checkov ID | What It Detects | Suggested Aegis ID | Severity |
|---|-----------|-----------------|-------------------|----------|
| 14 | CKV_AWS_31 | ElastiCache without auth token | AEGIS-AWS-514 | High |
| 15 | CKV_AWS_136 | ECR repository without KMS encryption | AEGIS-AWS-515 | Medium |
| 16 | CKV_AWS_351 | EMR in-transit encryption disabled | AEGIS-AWS-516 | Medium |
| 17 | CKV_AWS_349 | EMR local disk encryption disabled | AEGIS-AWS-517 | Medium |
| 18 | CKV_AWS_239 | DAX cluster without TLS | AEGIS-AWS-518 | Medium |
| 19 | CKV_AWS_228 | Elasticsearch with outdated TLS policy | AEGIS-AWS-519 | Medium |
| 20 | CKV_AWS_380 | Transfer Server with outdated security policy | AEGIS-AWS-520 | Medium |

### Tier 4: Authentication & Supply Chain (7 checks, 17 failures)

| # | Checkov ID | What It Detects | Suggested Aegis ID | Severity |
|---|-----------|-----------------|-------------------|----------|
| 21 | CKV_AWS_51 | ECR image tags not immutable | AEGIS-AWS-521 | Medium |
| 22 | CKV_AWS_359 | Neptune without IAM authentication | AEGIS-AWS-522 | Medium |
| 23 | CKV2_AWS_52 | OpenSearch without fine-grained access control | AEGIS-AWS-523 | Medium |
| 24 | CKV_AWS_391 | Redshift with default master username (`awsuser`) | AEGIS-AWS-524 | Medium |
| 25 | CKV_AWS_307 | SageMaker users with root access | AEGIS-AWS-525 | Medium |
| 26 | CKV2_AWS_68 | SageMaker IAM policy overly permissive | AEGIS-AWS-526 | Medium |
| 27 | CKV_AWS_336 | ECS container without read-only root filesystem | AEGIS-AWS-527 | Medium |

### Tier 5: Hardening (6 checks, 14 failures)

| # | Checkov ID | What It Detects | Suggested Aegis ID | Severity |
|---|-----------|-----------------|-------------------|----------|
| 28 | CKV_AWS_321 | Redshift without enhanced VPC routing | AEGIS-AWS-528 | Low |
| 29 | CKV2_AWS_42 | CloudFront without custom SSL certificate | AEGIS-AWS-529 | Low |
| 30 | CKV_AWS_192 | WAF without Log4j (CVE-2021-44228) rule | AEGIS-AWS-530 | Low |
| 31 | CKV2_AWS_47 | CloudFront WAF without Log4j AMR | AEGIS-AWS-531 | Low |
| 32 | CKV_AWS_371 | SageMaker notebook allows IMDSv1 | AEGIS-AWS-532 | Medium |
| 33 | CKV2_AWS_12 | Default security group allows all traffic | AEGIS-AWS-533 | Medium |

## What Checkov Gets Wrong (Noise)

These 12 checks fired on the **compliant fixture** — a deliberately hardened
configuration. They are false positives, not gaps:

| Checkov ID | Check Name | Why It's Noise |
|-----------|-----------|----------------|
| CKV2_AWS_62 | S3 event notifications | Not a security control |
| CKV_AWS_144 | S3 cross-region replication | Availability, not security |
| CKV2_AWS_61 | S3 lifecycle configuration | Cost optimization |
| CKV_AWS_272 | Lambda code signing | Fired despite valid config |
| CKV_AWS_116 | Lambda DLQ | Fired despite valid config |
| CKV_AWS_252 | CloudTrail SNS topic | Optional notification |
| CKV_AWS_35 | CloudTrail KMS encryption | Overly strict |
| CKV2_AWS_10 | CloudTrail CloudWatch integration | Optional |
| CKV2_AWS_41 | EC2 IAM role attached | Fired despite valid config |
| CKV2_AWS_64 | KMS key policy defined | Fired despite valid config |
| CKV2_AWS_5 | SG attached to resource | Fired despite valid config |
| CKV_AWS_13 | Password reuse prevention | Wants different value than secure default |

## Duplicates (Checkov Counts Twice)

12 checks are stricter KMS-CMK variants of misconfigurations Aegis already
catches with SSE-AES256. Example: Aegis flags unencrypted EBS (AEGIS-AWS-009);
Checkov fires both CKV_AWS_3 (unencrypted) AND CKV_AWS_189 (not CMK-encrypted).
These inflate Checkov's count without adding detection value.

## Hygiene (Not Security-Critical)

35 checks covering: S3 event notifications, lifecycle policies, cross-region
replication, RDS enhanced monitoring, performance insights, log exports,
CloudFront access logging, WAF logging, descriptions on security groups,
EBS optimization, MQ/ES/MSK audit logging, etc.

These are operational best practices, not vulnerabilities. A scanner optimized
for security signal should not count them equally with RCE paths.

## Recommendations

1. **Implement Tier 1 (IAM privilege analysis) first** — this is Checkov's
   biggest genuine advantage. 5 rules that catch privilege escalation paths
   Aegis currently misses entirely.

2. **Implement Tiers 2-3 (network + encryption)** — 15 rules covering
   real exposure and crypto gaps.

3. **Tiers 4-5 are nice-to-have** — 13 rules for completeness.

4. **Do NOT chase hygiene checks** — they dilute signal. Checkov's 221
   hygiene failures are not a detection lead; they're noise that makes
   triage harder.

5. **Total: 33 new rules (AEGIS-AWS-501–533)** would close every real gap,
   bringing Aegis to 205 AWS rules with strictly better signal-to-noise
   than Checkov.
