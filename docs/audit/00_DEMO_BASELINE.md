# AWS Security Detection Demonstration — Baseline (Phase 1)

**Date:** 2026-10-12
**Mission:** Small, reproducible, offline AWS IaC security demonstration of Aegis.
No AWS deployment, no credentials, no AWS API contact at any point.

## 1. Repository state

| Item | Value |
|---|---|
| Git commit | `2f6fae2ecdea65532fbed821cc4ff52d207da5bb` |
| Commit subject | Adapter semantic parity audit: verification + reproducibility |
| Branch | detached HEAD (no branch) |
| Working tree | clean (`git status --short` empty) |
| Go toolchain | go1.25.4 linux/amd64 |
| Aegis version | `aegis 1.0.0` (build/commit unknown — dev build) |

No modifications were made to the detection engine or rules before the initial scan.
The binary at `./aegis` was built from this exact commit via `go build -o aegis ./cmd/aegis/`.

## 2. CLI surface (verified via `./aegis scan --help`)

```
aegis scan <dir> [--format=text|json|sarif] [--rules=PACKS] [--advisories=file]
             [--fail-on=critical|high|medium|low] [--baseline=file] [--baseline-out=file]
             [--strict] [--compliance=FW] [--config=aegis.yaml] [--exclude=globs]
aegis fix  <dir> [--apply] [--rule=RULEID] [--format=text|json] [--force]
aegis serve [--addr=127.0.0.1:8734]
aegis quality-gate [--format=text|json] [--bench-dir=DIR] [--corpus-dir=DIR]
aegis doctor
aegis --version
```

Exit codes: 0 = clean / below `--fail-on`; 1 = findings; 2 = usage/scan error or `--strict` with unparseable files.

## 3. Rule registry

| Item | Value |
|---|---|
| Total rules loaded (`aegis doctor`) | **1,185** |
| AWS rules (`aws.Rules()`) | **482** (9 critical / 151 high / 187 medium / 135 low) |
| Critical/High with regression tests | 363/363 (quality gate) |

Rule ID range in source: `AEGIS-AWS-001` … `AEGIS-AWS-849`, plus `AEGIS-AWS-999`.

## 4. Supported input formats (9 adapters)

`terraform` (HCL) · `cloudformation` (JSON/YAML) · `arm` · `bicep` · `pulumi` (YAML) ·
`planjson` · `dockerfile` · `compose` · `manifests` (K8s).

This demo exercises **Terraform HCL** and **CloudFormation YAML** only.

## 5. AWS rule coverage by category (verified registered, not title-matched)

Each rule below was confirmed present in `aws.Rules()` with the stated severity
and an `AppliesTo` covering the relevant Terraform resource type.

| Category | Rule ID | Severity | Title |
|---|---|---|---|
| S3 storage | AEGIS-AWS-001 | high | S3 bucket without server-side encryption |
| S3 storage | AEGIS-AWS-002 | high | S3 bucket with public ACL |
| S3 storage | AEGIS-AWS-003 | critical | S3 bucket policy allows public principal |
| S3 storage | AEGIS-AWS-206 | high | S3 bucket without public access block |
| S3 storage | AEGIS-AWS-012 | medium | S3 bucket without versioning |
| IAM | AEGIS-AWS-006 | critical | IAM policy allows all actions on all resources |
| IAM | AEGIS-AWS-101 | critical | IAM role assumable by anyone |
| IAM | AEGIS-AWS-102 | high | IAM managed policy grants administrative access |
| Network | AEGIS-AWS-004 | high | Security group ingress open to the world |
| Network | AEGIS-AWS-005 | medium | Security group egress open to the world |
| Network | AEGIS-AWS-209 | medium | VPC without flow logs |
| EC2 | AEGIS-AWS-204 | high | EC2 instance without IMDSv2 enforcement |
| Storage | AEGIS-AWS-009 | medium | EBS volume without encryption |
| Storage | AEGIS-AWS-317 | high | EFS file system unencrypted |
| Database | AEGIS-AWS-007 | high | RDS instance without storage encryption |
| Database | AEGIS-AWS-011 | high | RDS instance publicly accessible |
| Database | AEGIS-AWS-008 | medium | RDS instance without deletion protection |
| Database | AEGIS-AWS-207 | medium | RDS instance without backup retention |
| KMS | AEGIS-AWS-335 | high | KMS key without rotation |
| Logging | AEGIS-AWS-010 | medium | CloudTrail without log file validation |
| Logging | AEGIS-AWS-336 | high | CloudTrail not multi-region |
| Serverless | AEGIS-AWS-307 | high | Lambda function env vars without KMS |
| Serverless | AEGIS-AWS-406 | high | Lambda permission grants invoke to everyone |
| Secrets | AEGIS-AWS-337 | medium | Secrets Manager rotation interval too long |
| Secrets | AEGIS-AWS-338 | high | SSM parameter stores plaintext secret |
| Messaging | AEGIS-AWS-341 | high | SNS topic without KMS encryption |
| Messaging | AEGIS-AWS-342 | high | SQS queue without encryption |
| Messaging | AEGIS-AWS-343 | high | SNS topic policy allows public principal |
| Messaging | AEGIS-AWS-344 | high | SQS queue policy allows public principal |
| LB / TLS | AEGIS-AWS-202 | critical | Load balancer listener uses plain HTTP |
| LB / TLS | AEGIS-AWS-324 | high | Load balancer listener with weak TLS policy |
| Containers | AEGIS-AWS-303 | medium | ECR repository without image scanning |
| API Gateway | AEGIS-AWS-403 | high | API Gateway method without authorization |
| Backup | AEGIS-AWS-392 | medium | Backup vault without KMS encryption |

34 scenarios selected. Categories NOT covered by this demo (no suitable AWS rule
found or out of demo scope): NACLs (no dedicated NACL rule in registry — verified
absent), WAF, GuardDuty, Config rules, Macie. These are documented as exclusions,
not claimed.

## 6. Quality gate at baseline

```
QUALITY GATE: PASS — release may proceed
  precision: 100.0% | recall: 100.0% (tp=355 fp=0 fn=0)
  rule-coverage: 363/363 critical/high tested
  performance: median=18.4ms p95=34.6ms (threshold p95≤500ms)
  parser-safety: 15/15 explicit
```

## 7. Exact commands used

```bash
cd ~/workspace/aegis-engine
git log -1 --format='%H %s'
git status --short
export PATH=~/workspace/toolchain/go/bin:$PATH
go version
go build -o aegis ./cmd/aegis/
./aegis --version
./aegis doctor
./aegis scan --help
./aegis quality-gate
```
