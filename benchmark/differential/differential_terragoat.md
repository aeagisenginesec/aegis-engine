# Differential Triage Report: Aegis vs KICS vs Checkov

## Summary

| Group | Meaning | Buckets |
|---|---|---|
| A | Detected by all three | 199 |
| B | Only Aegis detects | 257 |
| C | Only KICS and/or Checkov detect | 171 |
| D | Cannot be compared reliably | 349 |
| **Total buckets** | | 976 |

> Buckets are (normalized resource, canonical rule) pairs. A bucket may
> contain multiple raw findings (e.g. KICS duplicates).

## Group A — shared detection (top 15 by severity)

- **alicloud_oss_bucket.bad_bucket** / `AEGIS-ALI-002` — critical, info (scanners: aegis, checkov; n=2)
  - Alibaba Cloud OSS bucket accessible to public; OSS bucket publicly accessible
- **aws_instance.web_host** / `AEGIS-AWS-534` — critical, info (scanners: aegis, checkov; n=2)
  - Ensure no hard-coded secrets exist in EC2 user data; Secrets in EC2 user_data
- **google_bigquery_dataset.dataset** / `AEGIS-GCP-033` — critical, high (scanners: aegis, kics; n=2)
  - BigQuery Dataset Is Public; BigQuery dataset with public access
- **alicloud_oss_bucket.bad_bucket** / `AEGIS-ALI-001` — high, info (scanners: aegis, checkov; n=2)
  - Ensure OSS bucket is encrypted with Customer Master Key; OSS bucket without server-side encryption
- **alicloud_oss_bucket.trail** / `AEGIS-ALI-001` — high, medium, info (scanners: aegis, checkov, kics; n=3)
  - Ensure OSS bucket is encrypted with Customer Master Key; OSS Bucket Encryption Using CMK Disabled
- **aws_s3_bucket.data** / `AEGIS-AWS-001` — high (scanners: aegis, kics; n=2)
  - S3 Bucket Object Not Encrypted; S3 bucket without server-side encryption
- **aws_subnet.eks_subnet1** / `AEGIS-AWS-205` — high, medium (scanners: aegis, kics; n=2)
  - Subnet auto-assigns public IPs; VPC Subnet Assigns Public IP
- **aws_subnet.eks_subnet2** / `AEGIS-AWS-205` — high, medium (scanners: aegis, kics; n=2)
  - Subnet auto-assigns public IPs; VPC Subnet Assigns Public IP
- **aws_s3_bucket.data** / `AEGIS-AWS-206` — high, info (scanners: aegis, checkov; n=2)
  - Ensure that S3 bucket has a Public Access block; S3 bucket without public access block
- **aws_s3_bucket.data_science** / `AEGIS-AWS-206` — high, info (scanners: aegis, checkov; n=2)
  - Ensure that S3 bucket has a Public Access block; S3 bucket without public access block
- **aws_s3_bucket.financials** / `AEGIS-AWS-206` — high, info (scanners: aegis, checkov; n=2)
  - Ensure that S3 bucket has a Public Access block; S3 bucket without public access block
- **aws_s3_bucket.flowbucket** / `AEGIS-AWS-206` — high, info (scanners: aegis, checkov; n=2)
  - Ensure that S3 bucket has a Public Access block; S3 bucket without public access block
- **aws_s3_bucket.logs** / `AEGIS-AWS-206` — high, info (scanners: aegis, checkov; n=2)
  - Ensure that S3 bucket has a Public Access block; S3 bucket without public access block
- **aws_s3_bucket.operations** / `AEGIS-AWS-206` — high, info (scanners: aegis, checkov; n=2)
  - Ensure that S3 bucket has a Public Access block; S3 bucket without public access block
- **aws_eks_cluster.eks_cluster** / `AEGIS-AWS-304` — high, info (scanners: aegis, checkov; n=2)
  - EKS cluster without secrets encryption; Ensure EKS Cluster has Secrets Encryption Enabled

## Group B — Aegis-only (top 15 by severity)

- **google_storage_bucket_iam_binding.allow_public_read** / `AEGIS-GCP-001` — critical (scanners: aegis; n=1)
  - GCS bucket publicly readable via IAM
- **google_sql_database_instance.master_instance** / `AEGIS-GCP-040` — critical (scanners: aegis; n=1)
  - Cloud SQL instance allows connections from the internet
- **google_compute_firewall.allow_all** / `AEGIS-GCP-068` — critical (scanners: aegis; n=1)
  - Firewall allows all ports from the internet
- **oci_objectstorage_bucket.secretsquirrel** / `AEGIS-OCI-002` — critical (scanners: aegis; n=1)
  - Object Storage bucket with public access
- **aws_s3_bucket.data_science** / `AEGIS-AWS-001` — high (scanners: aegis; n=1)
  - S3 bucket without server-side encryption
- **aws_s3_bucket.financials** / `AEGIS-AWS-001` — high (scanners: aegis; n=1)
  - S3 bucket without server-side encryption
- **aws_s3_bucket.flowbucket** / `AEGIS-AWS-001` — high (scanners: aegis; n=1)
  - S3 bucket without server-side encryption
- **aws_s3_bucket.operations** / `AEGIS-AWS-001` — high (scanners: aegis; n=1)
  - S3 bucket without server-side encryption
- **aws_security_group.web-node** / `AEGIS-AWS-004` — high (scanners: aegis; n=2)
  - Security group ingress open to the world
- **aws_db_instance.default** / `AEGIS-AWS-007` — high (scanners: aegis; n=1)
  - RDS instance without storage encryption
- **aws_db_instance.default** / `AEGIS-AWS-011` — high (scanners: aegis; n=1)
  - RDS instance publicly accessible
- **aws_instance.db_app** / `AEGIS-AWS-204` — high (scanners: aegis; n=1)
  - EC2 instance without IMDSv2 enforcement
- **aws_instance.web_host** / `AEGIS-AWS-204` — high (scanners: aegis; n=1)
  - EC2 instance without IMDSv2 enforcement
- **aws_subnet.web_subnet** / `AEGIS-AWS-205` — high (scanners: aegis; n=1)
  - Subnet auto-assigns public IPs
- **aws_subnet.web_subnet2** / `AEGIS-AWS-205` — high (scanners: aegis; n=1)
  - Subnet auto-assigns public IPs

## Group C — KICS/Checkov-only (top 15 by severity)

- **google_sql_database_instance.terragoat-dev-master** / `AEGIS-GCP-007` — critical (scanners: kics; n=1)
  - SQL DB Instance Publicly Accessible
- **aws_db_instance.db1** / `AEGIS-AWS-007` — high (scanners: kics; n=1)
  - DB Instance Storage Not Encrypted
- **rnd_int.result}** / `AEGIS-AZURE-148` — high (scanners: kics; n=2)
  - Default Azure Storage Account Network Access Is Too Permissive
- **aws_ebs_snapshot.example_snapshot** / `AEGIS-AWS-009` — high (scanners: kics; n=1)
  - EBS Volume Snapshot Not Encrypted
- **eks_name.value** / `AEGIS-AWS-304` — high (scanners: kics; n=1)
  - EKS Cluster Encryption Disabled
- **google_container_cluster.terragoat-dev-cluster** / `AEGIS-GCP-009` — high (scanners: kics; n=1)
  - GKE Legacy Authorization Enabled
- **aws_iam_policy_document.policy** / `AEGIS-AWS-006` — high (scanners: kics; n=1)
  - IAM Policy Grants Full Permissions
- **aws_kms_key.logs_key** / `AEGIS-AWS-420` — high, info (scanners: checkov, kics; n=2)
  - Ensure KMS key Policy is defined; KMS Key With Vulnerable Policy
- **rnd_int.result}** / `AEGIS-AZURE-048` — high (scanners: kics; n=7)
  - MSSQL Server Public Network Access Enabled
- **rnd_int.result}** / `AEGIS-AZURE-169` — high (scanners: kics; n=1)
  - MySQL Server Public Access Enabled
- **alicloud_oss_bucket.wildwestfreeforall** / `AEGIS-ALI-002` — high (scanners: kics; n=1)
  - OSS Bucket Public Access Enabled
- **aws_rds_cluster.app9-rds-cluster** / `AEGIS-AWS-007` — high (scanners: kics; n=1)
  - RDS Storage Not Encrypted
- **aws_rds_cluster.app8-rds-cluster** / `AEGIS-AWS-007` — high (scanners: kics; n=1)
  - RDS Storage Not Encrypted
- **aws_rds_cluster.app4-rds-cluster** / `AEGIS-AWS-007` — high (scanners: kics; n=1)
  - RDS Storage Not Encrypted
- **aws_rds_cluster.app7-rds-cluster** / `AEGIS-AWS-007` — high (scanners: kics; n=1)
  - RDS Storage Not Encrypted

## Group C sample for manual labeling (30 items)

Classify each as: **real miss** (Aegis should detect), **duplicate**
(KICS/Checkov double-counts), **unsupported** (feature Aegis lacks),
**false positive** (competitor wrong), or **scope mismatch**
(outside Aegis's claimed coverage).

### C-01: google_sql_database_instance.terragoat-dev-master / AEGIS-GCP-007
- Severity: critical | Scanners: kics
- Titles: SQL DB Instance Publicly Accessible
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/gcp/big_data.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-02: aws_db_instance.db1 / AEGIS-AWS-007
- Severity: high | Scanners: kics
- Titles: DB Instance Storage Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/db-app.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-03: rnd_int.result} / AEGIS-AZURE-148
- Severity: high | Scanners: kics
- Titles: Default Azure Storage Account Network Access Is Too Permissive
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/azure/mssql.tf; ../home/hatch/workspace/terragoat-fresh/terraform/azure/storage.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-04: aws_ebs_snapshot.example_snapshot / AEGIS-AWS-009
- Severity: high | Scanners: kics
- Titles: EBS Volume Snapshot Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/ec2.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-05: eks_name.value / AEGIS-AWS-304
- Severity: high | Scanners: kics
- Titles: EKS Cluster Encryption Disabled
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/eks.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-06: google_container_cluster.terragoat-dev-cluster / AEGIS-GCP-009
- Severity: high | Scanners: kics
- Titles: GKE Legacy Authorization Enabled
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/gcp/gke.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-07: aws_iam_policy_document.policy / AEGIS-AWS-006
- Severity: high | Scanners: kics
- Titles: IAM Policy Grants Full Permissions
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/es.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-08: aws_kms_key.logs_key / AEGIS-AWS-420
- Severity: high, info | Scanners: checkov, kics
- Titles: Ensure KMS key Policy is defined; KMS Key With Vulnerable Policy
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/kms.tf; /workspace/terragoat-fresh/terraform/aws/kms.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-09: rnd_int.result} / AEGIS-AZURE-048
- Severity: high | Scanners: kics
- Titles: MSSQL Server Public Network Access Enabled
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/azure/mssql.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-10: rnd_int.result} / AEGIS-AZURE-169
- Severity: high | Scanners: kics
- Titles: MySQL Server Public Access Enabled
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/azure/sql.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-11: alicloud_oss_bucket.wildwestfreeforall / AEGIS-ALI-002
- Severity: high | Scanners: kics
- Titles: OSS Bucket Public Access Enabled
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/alicloud/bucket.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-12: aws_rds_cluster.app9-rds-cluster / AEGIS-AWS-007
- Severity: high | Scanners: kics
- Titles: RDS Storage Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/rds.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-13: aws_rds_cluster.app8-rds-cluster / AEGIS-AWS-007
- Severity: high | Scanners: kics
- Titles: RDS Storage Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/rds.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-14: aws_rds_cluster.app4-rds-cluster / AEGIS-AWS-007
- Severity: high | Scanners: kics
- Titles: RDS Storage Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/rds.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-15: aws_rds_cluster.app7-rds-cluster / AEGIS-AWS-007
- Severity: high | Scanners: kics
- Titles: RDS Storage Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/rds.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-16: aws_rds_cluster.app3-rds-cluster / AEGIS-AWS-007
- Severity: high | Scanners: kics
- Titles: RDS Storage Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/rds.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-17: aws_rds_cluster.app1-rds-cluster / AEGIS-AWS-007
- Severity: high | Scanners: kics
- Titles: RDS Storage Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/rds.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-18: aws_rds_cluster.app2-rds-cluster / AEGIS-AWS-007
- Severity: high | Scanners: kics
- Titles: RDS Storage Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/rds.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-19: aws_rds_cluster.app5-rds-cluster / AEGIS-AWS-007
- Severity: high | Scanners: kics
- Titles: RDS Storage Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/rds.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-20: aws_rds_cluster.app6-rds-cluster / AEGIS-AWS-007
- Severity: high | Scanners: kics
- Titles: RDS Storage Not Encrypted
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/rds.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-21: google_sql_database_instance.master_instance / AEGIS-GCP-008
- Severity: high, info | Scanners: checkov, kics
- Titles: Ensure all Cloud SQL database instance requires all incoming connections to use SSL; SQL DB Instance With SSL Disabled
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/gcp/big_data.tf; /workspace/terragoat-fresh/terraform/gcp/big_data.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-22: resource_prefix.value-sg / AEGIS-AWS-004
- Severity: high, medium | Scanners: kics
- Titles: HTTP Port Open To Internet; Security Group With Unrestricted Access To SSH; Sensitive Port Is Exposed To Entire Network; Unrestricted Security Group Ingress
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/ec2.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-23: rnd_int.result} / AEGIS-AZURE-008
- Severity: medium | Scanners: kics
- Titles: AD Admin Not Configured For SQL Server
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/azure/sql.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-24: azurerm_kubernetes_cluster.terragoat-aks-dev / AEGIS-AZURE-014
- Severity: medium | Scanners: kics
- Titles: AKS Private Cluster Disabled; AKS RBAC Disabled
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/azure/aks.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-25: rnd_int.result} / AEGIS-AZURE-061
- Severity: medium | Scanners: kics
- Titles: App Service Authentication Disabled; App Service HTTP2 Disabled
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/azure/app_service.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-26: rnd_int.result} / AEGIS-AZURE-115
- Severity: medium | Scanners: kics
- Titles: App Service Not Using Latest TLS Encryption Version
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/azure/app_service.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-27: rnd_int.result} / AEGIS-AZURE-118
- Severity: medium | Scanners: kics
- Titles: Azure App Service Client Certificate Disabled
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/azure/app_service.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-28: resource_prefix.value-dbapp / AEGIS-AWS-444
- Severity: medium | Scanners: kics
- Titles: EC2 Instance Has Public IP
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/db-app.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-29: resource_prefix.value-ec2 / AEGIS-AWS-444
- Severity: medium | Scanners: kics
- Titles: EC2 Instance Has Public IP
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/ec2.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_

### C-30: resource_prefix.value-dbapp / AEGIS-GCP-141
- Severity: medium | Scanners: kics
- Titles: EC2 Instance Monitoring Disabled
- Files: ../home/hatch/workspace/terragoat-fresh/terraform/aws/db-app.tf
- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_


## Group D — uncomparable (first 20)

- **uncomparable** / `0` — critical (scanners: kics; n=1)
  - Cloud Storage Anonymous or Publicly Accessible
- **uncomparable** / `1` — critical (scanners: kics; n=1)
  - RDS DB Instance Publicly Accessible
- **uncomparable** / `2` — critical (scanners: kics; n=1)
  - RDS DB Instance Publicly Accessible
- **uncomparable** / `3` — high (scanners: kics; n=1)
  - Aurora With Disabled at Rest Encryption
- **uncomparable** / `4` — high (scanners: kics; n=1)
  - Aurora With Disabled at Rest Encryption
- **uncomparable** / `5` — high (scanners: kics; n=1)
  - Aurora With Disabled at Rest Encryption
- **uncomparable** / `6` — high (scanners: kics; n=1)
  - Aurora With Disabled at Rest Encryption
- **uncomparable** / `7` — high (scanners: kics; n=1)
  - Aurora With Disabled at Rest Encryption
- **uncomparable** / `8` — high (scanners: kics; n=1)
  - Aurora With Disabled at Rest Encryption
- **uncomparable** / `9` — high (scanners: kics; n=1)
  - Aurora With Disabled at Rest Encryption
- **uncomparable** / `10` — high (scanners: kics; n=1)
  - Aurora With Disabled at Rest Encryption
- **uncomparable** / `11` — high (scanners: kics; n=1)
  - Aurora With Disabled at Rest Encryption
- **uncomparable** / `12` — high (scanners: kics; n=1)
  - EBS Volume Encryption Disabled
- **uncomparable** / `13` — high (scanners: kics; n=1)
  - ElasticSearch Not Encrypted At Rest
- **uncomparable** / `14` — high (scanners: kics; n=1)
  - Google Storage Bucket Level Access Disabled
- **uncomparable** / `15` — high (scanners: kics; n=1)
  - Hardcoded AWS Access Key
- **uncomparable** / `16` — high (scanners: kics; n=1)
  - Hardcoded AWS Access Key In Lambda
- **uncomparable** / `17` — high (scanners: kics; n=1)
  - Missing User Instruction
- **uncomparable** / `18` — high (scanners: kics; n=1)
  - Passwords And Secrets - AWS Access Key
- **uncomparable** / `19` — high (scanners: kics; n=1)
  - Passwords And Secrets - AWS Access Key
