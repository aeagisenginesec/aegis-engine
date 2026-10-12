# Compliance Framework Mappings

Aegis maps rule violations to controls in three compliance frameworks.
Mappings live in `internal/rules/compliance.go` (not on the rules), so
detection logic and framework coverage evolve independently.

## Frameworks

| ID | Framework |
|----|-----------|
| `CIS-AWS-1.5` | CIS Amazon Web Services Foundations Benchmark v1.5 |
| `NIST-800-53` | NIST Special Publication 800-53 Rev. 5 |
| `PCI-DSS-4.0` | PCI Data Security Standard v4.0 |

## CLI

Filter findings to one framework (shows control IDs in text output):

```
aegis scan ./infra --compliance CIS-AWS-1.5
aegis scan ./infra --compliance NIST-800-53 --format json
```

Unknown frameworks error with the available list:

```
$ aegis scan ./infra --compliance SOC2
aegis: unknown --compliance "SOC2" (want one of CIS-AWS-1.5, NIST-800-53, PCI-DSS-4.0)
```

Without the flag, every finding is enriched with all its mapped controls
(`compliance` field in JSON, `compliance:` line in text output).

## Mapping table

91 rules mapped (all 5 criticals + 86 highs). Only mapped where the
control genuinely applies.

| Rule | Title | CIS-AWS-1.5 | NIST-800-53 | PCI-DSS-4.0 |
|------|-------|-------------|-------------|-------------|
| AEGIS-AWS-003 | S3 bucket policy allows public principal | 2.1.1 | AC-3 | 1.4.1 |
| AEGIS-AWS-006 | IAM policy allows all actions on all resources | 1.16 | AC-6 | 7.2.1 |
| AEGIS-AWS-101 | IAM role assumable by anyone | 1.16 | AC-3 | 7.2.1 |
| AEGIS-AWS-104 | Public S3 exfiltration path | 2.1.1 | AC-4 | 1.4.1 |
| AEGIS-AWS-202 | Load balancer listener uses plain HTTP | — | SC-8 | 4.2.1 |
| AEGIS-AWS-001 | S3 bucket without server-side encryption | 2.1.1 | SC-28 | 3.5.1 |
| AEGIS-AWS-002 | S3 bucket with public ACL | 2.1.1 | AC-3 | 1.4.1 |
| AEGIS-AWS-004 | Security group ingress open to the world | 5.2 | SC-7 | 1.4.1 |
| AEGIS-AWS-007 | RDS instance without storage encryption | 2.3.1 | SC-28 | 3.5.1 |
| AEGIS-AWS-009 | EBS volume without encryption | 2.2.1 | SC-28 | 3.5.1 |
| AEGIS-AWS-010 | CloudTrail without log file validation | 3.2 | AU-9 | 10.3.1 |
| AEGIS-AWS-011 | RDS instance publicly accessible | 2.3.3 | AC-3 | 1.4.1 |
| AEGIS-AWS-102 | IAM managed policy grants administrative access | 1.16 | AC-6 | 7.2.1 |
| AEGIS-AWS-103 | Public RDS exposure path | 2.3.3 | AC-3 | 1.4.1 |
| AEGIS-AWS-201 | Load balancer internet-facing | — | SC-7 | 1.4.1 |
| AEGIS-AWS-203 | Load balancer not dropping invalid headers | — | SC-7 | — |
| AEGIS-AWS-204 | EC2 instance without IMDSv2 enforcement | — | AC-3 | — |
| AEGIS-AWS-205 | Subnet auto-assigns public IPs | — | SC-7 | 1.4.1 |
| AEGIS-AWS-206 | S3 bucket without public access block | 2.1.5 | AC-3 | 1.4.1 |
| AEGIS-AWS-301 | Launch template EBS volumes unencrypted | 2.2.1 | SC-28 | 3.5.1 |
| AEGIS-AWS-302 | ECS task definition with privileged container | — | CM-7 | 2.2.1 |
| AEGIS-AWS-304 | EKS cluster without secrets encryption | — | SC-28 | 3.5.1 |
| AEGIS-AWS-305 | EKS cluster with public endpoint | — | AC-3 | 1.4.1 |
| AEGIS-AWS-307 | Lambda function env vars without KMS | — | SC-28 | 3.5.1 |
| AEGIS-AWS-313 | DynamoDB table without customer-managed encryption | — | SC-28 | 3.5.1 |
| AEGIS-AWS-314 | Redshift cluster unencrypted | — | SC-28 | 3.5.1 |
| AEGIS-AWS-315 | Redshift cluster publicly accessible | — | AC-3 | 1.4.1 |
| AEGIS-AWS-317 | EFS file system unencrypted | — | SC-28 | 3.5.1 |
| AEGIS-AWS-318 | OpenSearch domain without node-to-node encryption | — | SC-28 | 3.5.1 |
| AEGIS-AWS-319 | OpenSearch domain without encryption at rest | — | SC-28 | 3.5.1 |
| AEGIS-AWS-324 | Load balancer listener with weak TLS policy | — | SC-8 | 4.2.1 |
| AEGIS-AWS-325 | CloudFront distribution allows HTTP | — | SC-8 | 4.2.1 |
| AEGIS-AWS-326 | API Gateway custom domain with weak TLS | — | SC-8 | 4.2.1 |
| AEGIS-AWS-329 | Load balancer target group uses plain HTTP | — | SC-8 | 4.2.1 |
| AEGIS-AWS-333 | Inline admin policy attached to role/user/group | 1.16 | AC-6 | 7.2.1 |
| AEGIS-AWS-335 | KMS key without rotation | 3.8 | SC-12 | 3.6.1 |
| AEGIS-AWS-336 | CloudTrail not multi-region | 3.1 | AU-2 | 10.3.1 |
| AEGIS-AWS-338 | SSM parameter stores plaintext secret | — | SC-28 | — |
| AEGIS-AWS-339 | Hardcoded credentials in resource config | — | IA-5 | — |
| AEGIS-AWS-341 | SNS topic without KMS encryption | — | SC-28 | 3.5.1 |
| AEGIS-AWS-342 | SQS queue without encryption | — | SC-28 | 3.5.1 |
| AEGIS-AWS-343 | SNS topic policy allows public principal | — | AC-3 | 1.4.1 |
| AEGIS-AWS-344 | SQS queue policy allows public principal | — | AC-3 | 1.4.1 |
| AEGIS-AWS-345 | MSK cluster without encryption | — | SC-28 | 3.5.1 |
| AEGIS-AWS-350 | Kinesis stream without encryption | — | SC-28 | 3.5.1 |
| AEGIS-AWS-351 | DocumentDB cluster unencrypted | — | SC-28 | 3.5.1 |
| AEGIS-AWS-352 | Neptune cluster unencrypted | — | SC-28 | 3.5.1 |
| AEGIS-AWS-354 | MemoryDB cluster without TLS | — | SC-8 | 4.2.1 |
| AEGIS-AWS-356 | DMS replication instance publicly accessible | — | AC-3 | 1.4.1 |
| AEGIS-AWS-357 | DMS endpoint without SSL | — | SC-8 | 4.2.1 |
| AEGIS-AWS-359 | Aurora cluster unencrypted | 2.3.1 | SC-28 | 3.5.1 |
| AEGIS-AWS-361 | EMR security configuration without at-rest encryption | — | SC-28 | 3.5.1 |
| AEGIS-AWS-363 | Athena workgroup without result encryption | — | SC-28 | 3.5.1 |
| AEGIS-AWS-364 | Glue data catalog without SSE-KMS encryption | — | SC-28 | 3.5.1 |
| AEGIS-AWS-366 | SageMaker notebook instance without customer-managed KMS key | — | SC-28 | 3.5.1 |
| AEGIS-AWS-368 | FSx Windows file system without customer-managed KMS key | — | SC-28 | 3.5.1 |
| AEGIS-AWS-369 | FSx Lustre file system without customer-managed KMS key | — | SC-28 | 3.5.1 |
| AEGIS-AWS-372 | API Gateway v2 CORS allows all origins | — | AC-3 | 1.4.1 |
| AEGIS-AWS-375 | EventBridge permission open to all principals | — | AC-3 | — |
| AEGIS-AWS-378 | WAFv2 Web ACL allows all traffic with no rules | — | SC-7 | 1.4.1 |
| AEGIS-AWS-379 | Transfer server allows plaintext FTP | — | SC-8 | 4.2.1 |
| AEGIS-AWS-381 | ECS service with public IP assignment | — | AC-3 | 1.4.1 |
| AEGIS-AWS-385 | CodeBuild project with privileged mode | — | CM-7 | 2.2.1 |
| AEGIS-AWS-390 | IoT policy with overly broad Allow statement | — | AC-6 | 7.2.1 |
| AEGIS-AWS-399 | RAM resource share allows external principals | — | AC-3 | — |
| AEGIS-AWS-401 | Classic ELB with plain-HTTP listener | — | SC-8 | 4.2.1 |
| AEGIS-AWS-403 | API Gateway method without authorization | — | IA-2 | — |
| AEGIS-AWS-404 | API Gateway v2 route without authorization | — | IA-2 | — |
| AEGIS-AWS-405 | CloudFront custom origin fetched over plain HTTP | — | SC-8 | 4.2.1 |
| AEGIS-AWS-406 | Lambda permission grants invoke to everyone | — | AC-3 | 7.2.1 |
| AEGIS-AWS-407 | Lambda function URL without authorization | — | IA-2 | — |
| AEGIS-AWS-408 | ECR repository policy allows public principal | — | AC-3 | 1.4.1 |
| AEGIS-AWS-410 | API Gateway API key hardcoded in config | — | IA-5 | — |
| AEGIS-AWS-411 | EC2 instance EBS volumes unencrypted | 2.2.1 | SC-28 | 3.5.1 |
| AEGIS-AWS-412 | ECS task definition with host networking | — | CM-7 | 2.2.1 |
| AEGIS-AWS-414 | S3 account public access block disabled | 2.1.5 | AC-3 | 1.4.1 |
| AEGIS-AWS-415 | EFS file system policy allows public principal | — | AC-3 | 1.4.1 |
| AEGIS-AWS-416 | FSx OpenZFS file system without customer-managed KMS key | — | SC-28 | 3.5.1 |
| AEGIS-AWS-420 | KMS key policy allows public principal | — | AC-3 | — |
| AEGIS-AWS-421 | Cognito identity pool allows unauthenticated identities | — | IA-2 | — |
| AEGIS-AWS-422 | SSO permission set with inline admin policy | 1.16 | AC-6 | 7.2.1 |
| AEGIS-AWS-424 | WorkSpaces volumes unencrypted | — | SC-28 | 3.5.1 |
| AEGIS-AWS-425 | Secrets Manager version with hardcoded secret | — | IA-5 | — |
| AEGIS-AWS-426 | SNS subscription over plaintext HTTP | — | SC-8 | 4.2.1 |
| AEGIS-AWS-428 | ElastiCache user with open access string | — | AC-3 | — |
| AEGIS-AWS-431 | Redshift Serverless workgroup publicly accessible | — | AC-3 | 1.4.1 |
| AEGIS-AWS-433 | VPC endpoint with public policy | — | AC-3 | 1.4.1 |
| AEGIS-AWS-436 | RDS proxy without TLS enforcement | — | SC-8 | 4.2.1 |
| AEGIS-AWS-441 | S3 access point policy allows public principal | 2.1.1 | AC-3 | 1.4.1 |
| AEGIS-AWS-443 | S3 bucket policy does not enforce TLS (SecureTransport) | 2.1.2 | SC-8 | 4.2.1 |
| AEGIS-AWS-444 | EC2 instance with public IP address | — | AC-3 | 1.4.1 |

## Design notes

- **Report-time enrichment.** Rules never set `Finding.Compliance`; the CLI
  populates it via `rules.ComplianceFor` after the scan. JSON output carries
  a `compliance` array; text output prints a `compliance:` line.
- **Unknown values stay quiet.** A finding only maps when the rule fires;
  the mapping never invents controls for unproven configurations.
- **Adding a framework** means adding refs in `complianceMap` — no rule
  changes, no engine changes.
