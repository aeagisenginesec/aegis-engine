# AWS Security Detection Demonstration — Report

**Date:** 2026-10-12
**Commit:** `2f6fae2ecdea65532fbed821cc4ff52d207da5bb` (clean tree, detached HEAD)
**Aegis:** 1.0.0, Go 1.25.4 linux/amd64, 1,185 rules (482 AWS)
**Environment:** local Linux sandbox, 2 vCPU — small local demonstration, not a production benchmark
**Offline:** no AWS deployment, no credentials, no AWS API contact at any point

## 1. Formats tested

Terraform HCL (34 scenarios) and CloudFormation YAML (8-scenario subset).
Both parsed with 100% success, zero skipped/failed files.

## 2. Corpus

`tests/demos/aws-security-demo/` — 84 fixtures:
- `vulnerable/` — 34 Terraform HCL fixtures, one per scenario
- `secure/` — 34 matching Terraform HCL controls (minimal diff from vulnerable)
- `cfn-vulnerable/` / `cfn-secure/` — 8 CloudFormation YAML pairs
- `manifest.json` — machine-readable expectations (rule IDs/severities read from the real registry)

34 scenarios across S3, IAM, network, EC2, RDS, EBS/EFS, KMS, CloudTrail,
Lambda, Secrets/SSM, SNS/SQS, load balancers/TLS, ECR, API Gateway, backup.
Excluded (no suitable rule or out of scope): NACLs, WAF, GuardDuty, Config — documented, not claimed.

## 3. Results

### Scenario detection rate (Terraform)

**31 / 34 vulnerable scenarios detected** (91.2%)

| # | Rule | Severity | Result | Notes |
|---|---|---|---|---|
| 01 | AEGIS-AWS-002 | high | HIT | S3 public ACL |
| 02 | AEGIS-AWS-003 | critical | HIT | S3 public policy |
| 03 | AEGIS-AWS-001 | high | HIT | S3 no encryption |
| 04 | AEGIS-AWS-206 | high | HIT | S3 no public access block |
| 05 | AEGIS-AWS-012 | medium | HIT | S3 no versioning |
| 06 | AEGIS-AWS-004 | high | HIT | SG open SSH |
| 07 | AEGIS-AWS-005 | medium | HIT | SG open egress |
| 08 | AEGIS-AWS-006 | critical | HIT | IAM admin wildcard |
| 09 | AEGIS-AWS-101 | critical | HIT | IAM open trust |
| 10 | AEGIS-AWS-102 | high | **MISS** | Defect D1: coverage gap (see §5) |
| 11 | AEGIS-AWS-007 | high | HIT | RDS unencrypted |
| 12 | AEGIS-AWS-011 | high | HIT | RDS public |
| 13 | AEGIS-AWS-008 | medium | HIT | RDS no deletion protection |
| 14 | AEGIS-AWS-207 | medium | HIT | RDS no backup |
| 15 | AEGIS-AWS-009 | medium | HIT | EBS unencrypted |
| 16 | AEGIS-AWS-010 | medium | HIT | CloudTrail no validation |
| 17 | AEGIS-AWS-336 | high | HIT | CloudTrail single-region |
| 18 | AEGIS-AWS-204 | high | HIT | EC2 no IMDSv2 |
| 19 | AEGIS-AWS-209 | medium | HIT* | Fixture corrected (bare VPC skipped by documented design); HIT after adding subnet |
| 20 | AEGIS-AWS-202 | critical | HIT | LB plain HTTP |
| 21 | AEGIS-AWS-324 | high | HIT | LB weak TLS |
| 22 | AEGIS-AWS-307 | high | HIT | Lambda env no KMS (but see D2 — also FPs on secure) |
| 23 | AEGIS-AWS-406 | high | HIT | Lambda public invoke |
| 24 | AEGIS-AWS-335 | high | HIT | KMS no rotation |
| 25 | AEGIS-AWS-337 | medium | HIT | Secrets rotation 180d |
| 26 | AEGIS-AWS-338 | high | HIT | SSM plaintext |
| 27 | AEGIS-AWS-341 | high | HIT | SNS no KMS |
| 28 | AEGIS-AWS-342 | high | HIT* | Fixture corrected (absent = provider-default SSE-SQS per documented rule behavior); HIT with explicit `sqs_managed_sse_enabled=false` |
| 29 | AEGIS-AWS-343 | high | **MISS** | Defect D3: policy with resource reference silently skipped |
| 30 | AEGIS-AWS-344 | high | **MISS** | Defect D3: same root cause |
| 31 | AEGIS-AWS-317 | high | HIT | EFS unencrypted |
| 32 | AEGIS-AWS-303 | medium | HIT | ECR no scanning |
| 33 | AEGIS-AWS-403 | high | HIT | API GW no auth |
| 34 | AEGIS-AWS-392 | medium | HIT | Backup vault no KMS |

### Scenario detection rate (CloudFormation)

**8 / 8 vulnerable scenarios detected** (100%), **0 / 8** secure controls incorrectly flagged.
Cross-format parity holds on all tested scenarios.

### Secure controls incorrectly flagged (tested condition only)

**1 / 34** (Terraform), **0 / 8** (CloudFormation):
- Scenario 22: AEGIS-AWS-307 fired on the secure fixture → Defect D2 (false positive).

Note: secure fixtures produced 145 total findings across the corpus, but all
except D2 were genuine additional issues on *other* conditions (e.g. an S3
fixture hardened for ACL still lacking encryption) — out of scope for the tested
condition, not false positives on it.

## 4. Evidence, severity, determinism, completeness

- **Evidence accuracy:** sampled 5 findings (TF + CFN) — all identified the correct
  resource, correct attribute, correct actual value, and precise line spans.
  Remediation text and compliance mappings present on all.
- **Severity consistency:** all 31 hit scenarios matched the registry severity exactly.
- **Determinism:** 3 consecutive full-corpus scans produced byte-identical output
  (SHA-256 `364671a9…` ×3).
- **Scan completeness:** 34/34 TF + 8/8 CFN files parsed, 0 skipped, 0 failed,
  0 diagnostics. Exit code 1 on corpora with findings (correct per CLI contract).
- **SARIF:** valid 2.1.0, 90 rules, 195 results on the vulnerable TF corpus.

## 5. Confirmed defects (documented, NOT fixed — per mission rules)

**D1 — AEGIS-AWS-666 coverage gap (rule logic).**
Attaching AWS-managed `AdministratorAccess` via `managed_policy_arns` on
`aws_iam_role` (scenario 10) is detected by no rule. AEGIS-AWS-666
("policy attachment grants AdministratorAccess") only applies to
`aws_iam_policy_attachment` resources; AEGIS-AWS-102 only inspects inline
`aws_iam_policy` documents. The `aws_iam_role_policy_attachment`,
`aws_iam_user_policy_attachment`, `aws_iam_group_policy_attachment`, and
`managed_policy_arns` patterns are all missed. Severity: high — silent false negative
on a critical privilege-escalation pattern.

**D2 — AEGIS-AWS-307 false positive (rule logic).**
The rule checks for `kms_key_arn` *inside* the `environment` block, but the real
Terraform attribute is top-level on `aws_lambda_function`. Result: fires on
correctly configured functions (scenario 22 secure fixture), and its evidence
attribute path (`environment.kms_key_arn`) does not exist in the provider schema.
Severity: high — false positive on a high-severity rule erodes trust.

**D3 — AEGIS-AWS-343/344 silent skip on unresolvable policy references (rule logic).**
When an SNS/SQS policy document contains a resource reference
(e.g. `Resource = aws_sns_topic.demo.arn` inside `jsonencode`), the policy string
resolves to unknown and the rule returns nil with **no diagnostic** —
contradicting the documented explicit-uncertainty philosophy. Verified: same
policy with a literal ARN fires correctly. This is an extremely common
real-world pattern. Severity: medium — silent false negative, no visibility.

## 6. Performance (small local demonstration)

| Scan | Duration |
|---|---|
| TF vulnerable corpus (34 files) | 19 ms |
| TF secure corpus (34 files) | 18 ms |
| CFN corpora (8 files each) | 13–18 ms |
| Individual fixture | <5 ms each |

Not a production benchmark — single small fixtures on a sandbox VM.

## 7. Exclusions and limitations of this demo

- 34 scenarios sample the 482-rule AWS pack; not exhaustive.
- No precision/recall claimed — expected findings were author-labeled, not independently reviewed.
- NACLs, WAF, GuardDuty, Config, Macie not exercised (no suitable rules found).
- Pulumi/ARM/Bicep formats not exercised in this demo (covered by the parity audit).
- Two fixtures were corrected during the demo (19: bare-VPC skip is documented rule
  behavior; 28: absent-attribute = provider default is documented rule behavior).
  Both corrections are recorded above; neither changes a rule.

## 8. Reproduction

```bash
cd ~/workspace/aegis-engine
git log -1 --format=%H   # expect 2f6fae2ecdea65532fbed821cc4ff52d207da5bb
export PATH=~/workspace/toolchain/go/bin:$PATH
go build -o aegis ./cmd/aegis/
./aegis scan tests/demos/aws-security-demo/vulnerable --format=json --rules=aws
./aegis scan tests/demos/aws-security-demo/secure    --format=json --rules=aws
./aegis scan tests/demos/aws-security-demo/cfn-vulnerable --format=json --rules=aws
```

Raw outputs: `docs/audit/demo-raw/` (per-fixture JSON + meta, corpus JSON + SARIF + meta, determinism hashes).
Expectations: `tests/demos/aws-security-demo/manifest.json`.

## 9. Verdict

Aegis detected **31/34** Terraform scenarios and **8/8** CloudFormation scenarios,
with accurate evidence, correct severities, deterministic output, and complete
scan accounting. Three genuine defects were found (one coverage gap, one false
positive, one silent-skip limitation) — all documented above for follow-up with
regression tests. The engine is strong on the tested surface; D1–D3 are the
concrete items standing between this demo and a clean sheet.
