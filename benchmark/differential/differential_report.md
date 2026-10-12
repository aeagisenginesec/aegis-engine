# Differential Triage Report: Aegis vs KICS vs Checkov

## Summary

| Group | Meaning | Buckets |
|---|---|---|
| A | Detected by all three | 473 |
| B | Only Aegis detects | 270 |
| C | Only KICS and/or Checkov detect | 105 |
| D | Cannot be compared reliably | 571 |
| **Total buckets** | | 1419 |

> Buckets are (normalized resource, canonical rule) pairs. A bucket may
> contain multiple raw findings (e.g. KICS duplicates).

## Group A — shared detection (top 15 by severity)

- **aws_s3_bucket_acl.pa0** / `AEGIS-AWS-002` — critical, high (scanners: aegis, kics; n=2)
  - S3 Bucket ACL Allows Read Or Write to All Users; S3 bucket with public ACL
- **aws_s3_bucket_acl.pa1** / `AEGIS-AWS-002` — critical, high (scanners: aegis, kics; n=2)
  - S3 Bucket ACL Allows Read Or Write to All Users; S3 bucket with public ACL
- **aws_s3_bucket_acl.pa2** / `AEGIS-AWS-002` — critical, high (scanners: aegis, kics; n=2)
  - S3 Bucket ACL Allows Read Or Write to All Users; S3 bucket with public ACL
- **aws_s3_bucket_acl.pa3** / `AEGIS-AWS-002` — critical, high (scanners: aegis, kics; n=2)
  - S3 Bucket ACL Allows Read Or Write to All Users; S3 bucket with public ACL
- **aws_s3_bucket_policy.pp0** / `AEGIS-AWS-003` — critical, high, info (scanners: aegis, checkov, kics; n=4)
  - Ensure S3 bucket does not allow an action with any Principal; S3 Bucket Access to Any Principal
- **aws_s3_bucket_policy.pp1** / `AEGIS-AWS-003` — critical, high, info (scanners: aegis, checkov, kics; n=4)
  - Ensure S3 bucket does not allow an action with any Principal; S3 Bucket Access to Any Principal
- **aws_s3_bucket_policy.pp2** / `AEGIS-AWS-003` — critical, high, info (scanners: aegis, checkov, kics; n=4)
  - Ensure S3 bucket does not allow an action with any Principal; S3 Bucket Access to Any Principal
- **aws_s3_bucket_policy.pp3** / `AEGIS-AWS-003` — critical, high, info (scanners: aegis, checkov, kics; n=4)
  - Ensure S3 bucket does not allow an action with any Principal; S3 Bucket Access to Any Principal
- **aws_iam_policy.adm0** / `AEGIS-AWS-006` — critical, high, medium (scanners: aegis, kics; n=3)
  - IAM Policies With Full Privileges; IAM Policy Grants Full Permissions
- **aws_iam_policy.adm1** / `AEGIS-AWS-006` — critical, high, medium (scanners: aegis, kics; n=3)
  - IAM Policies With Full Privileges; IAM Policy Grants Full Permissions
- **aws_iam_policy.adm2** / `AEGIS-AWS-006` — critical, high, medium (scanners: aegis, kics; n=3)
  - IAM Policies With Full Privileges; IAM Policy Grants Full Permissions
- **aws_iam_policy.adm0** / `AEGIS-AWS-501` — critical, info (scanners: aegis, checkov; n=2)
  - Ensure IAM policies does not allow privilege escalation; IAM policy allows privilege escalation (create policy + attach policy)
- **aws_iam_policy.adm1** / `AEGIS-AWS-501` — critical, info (scanners: aegis, checkov; n=2)
  - Ensure IAM policies does not allow privilege escalation; IAM policy allows privilege escalation (create policy + attach policy)
- **aws_iam_policy.adm2** / `AEGIS-AWS-501` — critical, info (scanners: aegis, checkov; n=2)
  - Ensure IAM policies does not allow privilege escalation; IAM policy allows privilege escalation (create policy + attach policy)
- **aws_iam_policy.adm0** / `AEGIS-AWS-502` — critical, info (scanners: aegis, checkov; n=2)
  - Ensure IAM policies does not allow credentials exposure; IAM policy allows privilege escalation via iam:PassRole on * with compute launch

## Group B — Aegis-only (top 15 by severity)

- **aws_s3_bucket.pa0** / `AEGIS-AWS-104` — critical (scanners: aegis; n=1)
  - Public S3 exfiltration path
- **aws_s3_bucket.pa1** / `AEGIS-AWS-104` — critical (scanners: aegis; n=1)
  - Public S3 exfiltration path
- **aws_s3_bucket.pa2** / `AEGIS-AWS-104` — critical (scanners: aegis; n=1)
  - Public S3 exfiltration path
- **aws_s3_bucket.pa3** / `AEGIS-AWS-104` — critical (scanners: aegis; n=1)
  - Public S3 exfiltration path
- **aws_s3_bucket.pp0** / `AEGIS-AWS-104` — critical (scanners: aegis; n=1)
  - Public S3 exfiltration path
- **aws_s3_bucket.pp1** / `AEGIS-AWS-104` — critical (scanners: aegis; n=1)
  - Public S3 exfiltration path
- **aws_s3_bucket.pp2** / `AEGIS-AWS-104` — critical (scanners: aegis; n=1)
  - Public S3 exfiltration path
- **aws_s3_bucket.pp3** / `AEGIS-AWS-104` — critical (scanners: aegis; n=1)
  - Public S3 exfiltration path
- **aws_lb_listener.albl0** / `AEGIS-AWS-202` — critical (scanners: aegis; n=1)
  - Load balancer listener uses plain HTTP
- **aws_lb_listener.albl1** / `AEGIS-AWS-202` — critical (scanners: aegis; n=1)
  - Load balancer listener uses plain HTTP
- **aws_s3_bucket.pa0** / `AEGIS-AWS-001` — high (scanners: aegis; n=1)
  - S3 bucket without server-side encryption
- **aws_s3_bucket.pa1** / `AEGIS-AWS-001` — high (scanners: aegis; n=1)
  - S3 bucket without server-side encryption
- **aws_s3_bucket.pa2** / `AEGIS-AWS-001` — high (scanners: aegis; n=1)
  - S3 bucket without server-side encryption
- **aws_s3_bucket.pa3** / `AEGIS-AWS-001` — high (scanners: aegis; n=1)
  - S3 bucket without server-side encryption
- **aws_s3_bucket.pp0** / `AEGIS-AWS-001` — high (scanners: aegis; n=1)
  - S3 bucket without server-side encryption

## Group C — KICS/Checkov-only (top 15 by severity)

- **aws_kms_key.k0** / `AEGIS-AWS-420` — high, info (scanners: checkov, kics; n=2)
  - Ensure KMS key Policy is defined; KMS Key With Vulnerable Policy
- **aws_kms_key.k2** / `AEGIS-AWS-420` — high, info (scanners: checkov, kics; n=2)
  - Ensure KMS key Policy is defined; KMS Key With Vulnerable Policy
- **aws_kms_key.k1** / `AEGIS-AWS-420` — high, info (scanners: checkov, kics; n=2)
  - Ensure KMS key Policy is defined; KMS Key With Vulnerable Policy
- **aws_redshift_cluster.rs1** / `AEGIS-AWS-315` — high, info (scanners: checkov, kics; n=2)
  - Redshift Publicly Accessible; Redshift cluster should not be publicly accessible
- **aws_redshift_cluster.rs0** / `AEGIS-AWS-315` — high, info (scanners: checkov, kics; n=2)
  - Redshift Publicly Accessible; Redshift cluster should not be publicly accessible
- **aws_api_gateway_domain_name.ag1** / `AEGIS-AWS-403` — medium (scanners: kics; n=1)
  - API Gateway Without Security Policy
- **aws_api_gateway_domain_name.ag0** / `AEGIS-AWS-403` — medium (scanners: kics; n=1)
  - API Gateway Without Security Policy
- **aws_instance.imds2** / `AEGIS-AWS-444` — medium (scanners: kics; n=1)
  - EC2 Instance Has Public IP
- **aws_instance.imds1** / `AEGIS-AWS-444` — medium (scanners: kics; n=1)
  - EC2 Instance Has Public IP
- **aws_instance.imds0** / `AEGIS-AWS-444` — medium (scanners: kics; n=1)
  - EC2 Instance Has Public IP
- **aws_instance.imds3** / `AEGIS-AWS-444` — medium (scanners: kics; n=1)
  - EC2 Instance Has Public IP
- **aws_ecs_task_definition.ecs1** / `AEGIS-AWS-302` — medium (scanners: kics; n=1)
  - ECS Task Definition Network Mode Not Recommended
- **aws_ecs_task_definition.ecs2** / `AEGIS-AWS-302` — medium (scanners: kics; n=1)
  - ECS Task Definition Network Mode Not Recommended
- **aws_ecs_task_definition.ecs0** / `AEGIS-AWS-302` — medium (scanners: kics; n=1)
  - ECS Task Definition Network Mode Not Recommended
- **aws_iot_policy.iot1** / `AEGIS-AWS-408` — medium (scanners: kics; n=1)
  - Policy Without Principal

## Group C sample for manual labeling (30 items)

Classify each as: **real miss** (Aegis should detect), **duplicate**
(KICS/Checkov double-counts), **unsupported** (feature Aegis lacks),
**false positive** (competitor wrong), or **scope mismatch**
(outside Aegis's claimed coverage).

### C-01: aws_kms_key.k0 / AEGIS-AWS-420
- Severity: high, info | Scanners: checkov, kics
- Titles: Ensure KMS key Policy is defined; KMS Key With Vulnerable Policy
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf; /workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-02: aws_kms_key.k2 / AEGIS-AWS-420
- Severity: high, info | Scanners: checkov, kics
- Titles: Ensure KMS key Policy is defined; KMS Key With Vulnerable Policy
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf; /workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-03: aws_kms_key.k1 / AEGIS-AWS-420
- Severity: high, info | Scanners: checkov, kics
- Titles: Ensure KMS key Policy is defined; KMS Key With Vulnerable Policy
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf; /workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-04: aws_redshift_cluster.rs1 / AEGIS-AWS-315
- Severity: high, info | Scanners: checkov, kics
- Titles: Redshift Publicly Accessible; Redshift cluster should not be publicly accessible
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf; /workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-05: aws_redshift_cluster.rs0 / AEGIS-AWS-315
- Severity: high, info | Scanners: checkov, kics
- Titles: Redshift Publicly Accessible; Redshift cluster should not be publicly accessible
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf; /workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-06: aws_api_gateway_domain_name.ag1 / AEGIS-AWS-403
- Severity: medium | Scanners: kics
- Titles: API Gateway Without Security Policy
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-07: aws_api_gateway_domain_name.ag0 / AEGIS-AWS-403
- Severity: medium | Scanners: kics
- Titles: API Gateway Without Security Policy
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-08: aws_instance.imds2 / AEGIS-AWS-444
- Severity: medium | Scanners: kics
- Titles: EC2 Instance Has Public IP
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-09: aws_instance.imds1 / AEGIS-AWS-444
- Severity: medium | Scanners: kics
- Titles: EC2 Instance Has Public IP
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-10: aws_instance.imds0 / AEGIS-AWS-444
- Severity: medium | Scanners: kics
- Titles: EC2 Instance Has Public IP
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-11: aws_instance.imds3 / AEGIS-AWS-444
- Severity: medium | Scanners: kics
- Titles: EC2 Instance Has Public IP
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-12: aws_ecs_task_definition.ecs1 / AEGIS-AWS-302
- Severity: medium | Scanners: kics
- Titles: ECS Task Definition Network Mode Not Recommended
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-13: aws_ecs_task_definition.ecs2 / AEGIS-AWS-302
- Severity: medium | Scanners: kics
- Titles: ECS Task Definition Network Mode Not Recommended
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-14: aws_ecs_task_definition.ecs0 / AEGIS-AWS-302
- Severity: medium | Scanners: kics
- Titles: ECS Task Definition Network Mode Not Recommended
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-15: aws_iot_policy.iot1 / AEGIS-AWS-408
- Severity: medium | Scanners: kics
- Titles: Policy Without Principal
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-16: aws_iot_policy.iot0 / AEGIS-AWS-408
- Severity: medium | Scanners: kics
- Titles: Policy Without Principal
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-17: aws_sqs_queue.q1 / AEGIS-AWS-342
- Severity: medium, info | Scanners: checkov, kics
- Titles: Ensure all data stored in the SQS queue is encrypted; SQS With SSE Disabled
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf; /workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-18: aws_sqs_queue.q2 / AEGIS-AWS-342
- Severity: medium, info | Scanners: checkov, kics
- Titles: Ensure all data stored in the SQS queue is encrypted; SQS With SSE Disabled
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf; /workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-19: aws_sqs_queue.q0 / AEGIS-AWS-342
- Severity: medium, info | Scanners: checkov, kics
- Titles: Ensure all data stored in the SQS queue is encrypted; SQS With SSE Disabled
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf; /workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-20: aws_vpc.v / AEGIS-AWS-438
- Severity: medium | Scanners: kics
- Titles: VPC Without Network Firewall
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-21: aws_ecr_repository.ecr2 / AEGIS-AWS-408
- Severity: low | Scanners: kics
- Titles: ECR Repository Without Policy
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-22: aws_ecr_repository.ecr0 / AEGIS-AWS-408
- Severity: low | Scanners: kics
- Titles: ECR Repository Without Policy
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-23: aws_ecr_repository.ecr1 / AEGIS-AWS-408
- Severity: low | Scanners: kics
- Titles: ECR Repository Without Policy
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-24: aws_instance.pip2 / AEGIS-AWS-396
- Severity: low | Scanners: kics
- Titles: Instance With No VPC
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-25: aws_instance.pip1 / AEGIS-AWS-396
- Severity: low | Scanners: kics
- Titles: Instance With No VPC
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-26: aws_instance.imds1 / AEGIS-AWS-396
- Severity: low | Scanners: kics
- Titles: Instance With No VPC
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-27: aws_instance.imds3 / AEGIS-AWS-396
- Severity: low | Scanners: kics
- Titles: Instance With No VPC
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-28: aws_instance.pip0 / AEGIS-AWS-396
- Severity: low | Scanners: kics
- Titles: Instance With No VPC
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-29: aws_instance.imds2 / AEGIS-AWS-396
- Severity: low | Scanners: kics
- Titles: Instance With No VPC
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-30: aws_instance.imds0 / AEGIS-AWS-396
- Severity: low | Scanners: kics
- Titles: Instance With No VPC
- Files: ../home/hatch/workspace/terraform/vuln-200/main.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_


## Group D — uncomparable (first 20)

- **uncomparable** / `0` — critical (scanners: kics; n=1)
  - RDS DB Instance Publicly Accessible
- **uncomparable** / `1` — critical (scanners: kics; n=1)
  - RDS DB Instance Publicly Accessible
- **uncomparable** / `2` — critical (scanners: kics; n=1)
  - RDS DB Instance Publicly Accessible
- **uncomparable** / `3` — high (scanners: kics; n=1)
  - AmazonMQ Broker Encryption Disabled
- **uncomparable** / `4` — high (scanners: kics; n=1)
  - AmazonMQ Broker Encryption Disabled
- **uncomparable** / `5` — high (scanners: kics; n=1)
  - DOCDB Cluster Without KMS
- **uncomparable** / `6` — high (scanners: kics; n=1)
  - DOCDB Cluster Without KMS
- **uncomparable** / `7` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `8` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `9` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `10` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `11` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `12` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `13` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `14` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `15` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `16` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `17` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `18` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
- **uncomparable** / `19` — high (scanners: kics; n=1)
  - Passwords And Secrets - Generic Password
