# Checkov Gap Closure Analysis — TerraGoat

**Date:** 2026-10-11
**Status:** ✅ COMPLETE — Aegis surpasses Checkov
**Final:** Aegis 472 vs Checkov 467 (+5)

## Final Results

| Metric | Checkov | Aegis | Delta |
|--------|---------|-------|-------|
| Total findings | 467 | **472** | **+5** |
| AWS | 215 | **218** | **+3** |
| Azure | 174 | **189** | **+15** |
| GCP | 56 | 56 | 0 (tied) |
| Other (Alibaba/OCI) | 22 | 9 | -13 (out of scope) |

## Summary (Original State)

| Metric | Checkov | Aegis | Gap |
|--------|---------|-------|-----|
| Total findings | 467 | 263 | -204 |
| AWS | 215 | 153 | -62 |
| Azure | 174 | 67 | -107 |
| GCP | 56 | 34 | -22 |
| Other (Alibaba/OCI) | 22 | 0 | -22 (out of scope) |

## High-Frequency Gaps (>=5x occurrences)

### RDS Cluster (Aurora) — 81 findings across 9 checks

| Checkov Check | Count | What It Detects | Aegis Equivalent |
|---------------|-------|-----------------|------------------|
| CKV_AWS_96 | 9x | Aurora encrypted at rest | ✅ YES (auroraUnencrypted) |
| CKV_AWS_325 | 9x | RDS Cluster audit logging (MySQL) | ❌ NO |
| CKV_AWS_326 | 9x | Aurora backtracking enabled | ❌ NO |
| CKV_AWS_313 | 9x | Copy tags to snapshots | ❌ NO |
| CKV_AWS_327 | 9x | Encrypted with KMS CMKs (not just encrypted) | ❌ NO (only generic encryption) |
| CKV_AWS_162 | 9x | IAM authentication enabled | ✅ YES (auroraNoIAMAuth) |
| CKV_AWS_324 | 9x | Enhanced monitoring / Performance Insights | ❌ NO |
| CKV_AWS_139 | 9x | Deletion protection enabled | ✅ YES |
| CKV2_AWS_8 | 9x | AWS Backup plan configured | ❌ NO |

**Missing: 6 checks × 9 = 54 findings**

### Azure MSSQL — 60 findings across 8 checks

| Checkov Check | Count | What It Detects | Aegis Equivalent |
|---------------|-------|-----------------|------------------|
| CKV_AZURE_23 | 8x | Auditing set to 'On' | ❌ NO |
| CKV_AZURE_24 | 8x | Auditing retention >90 days | ❌ NO |
| CKV_AZURE_25 | 8x | Threat detection types = 'All' | ❌ NO |
| CKV_AZURE_27 | 8x | Email service/co-administrators enabled | ❌ NO |
| CKV_AZURE_52 | 7x | Latest TLS version | ❌ NO |
| CKV_AZURE_113 | 7x | Public network access disabled | ❌ NO |
| CKV2_AZURE_27 | 7x | Azure AD authentication enabled | ❌ NO |
| CKV2_AZURE_45 | 7x | Private endpoint configured | ❌ NO |

**Missing: 8 checks, ~60 findings**

### S3 — 34 findings across 6 checks

| Checkov Check | Count | What It Detects | Aegis Equivalent |
|---------------|-------|-----------------|------------------|
| CKV2_AWS_62 | 6x | Event notifications enabled | ✅ YES (hygiene, low) |
| CKV2_AWS_6 | 6x | Public access block (separate resource) | ✅ YES |
| CKV2_AWS_61 | 6x | Lifecycle configuration | ✅ YES (hygiene, low) |
| CKV_AWS_144 | 6x | Cross-region replication | ✅ YES (hygiene, low) |
| CKV_AWS_145 | 5x | Encrypted with KMS (not just SSE-S3) | ⚠️ PARTIAL |
| CKV_AWS_18 | 5x | Access logging enabled | ✅ YES |

**Note:** Aegis HAS these rules but they may not fire due to severity filtering or cross-resource correlation gaps. Need investigation.

## Strategy to Surpass (need +204)

### Phase 1: Build missing RDS Cluster rules (+54)
- AEGIS-AWS-631: RDS Cluster audit logging
- AEGIS-AWS-632: Aurora backtracking
- AEGIS-AWS-633: Copy tags to snapshots
- AEGIS-AWS-634: KMS CMK encryption (specific)
- AEGIS-AWS-635: Enhanced monitoring / Performance Insights
- AEGIS-AWS-636: AWS Backup plan (cross-resource)

### Phase 2: Build missing Azure MSSQL rules (+60)
- AEGIS-AZURE-101: Auditing enabled
- AEGIS-AZURE-102: Auditing retention >90 days
- AEGIS-AZURE-103: Threat detection = All
- AEGIS-AZURE-104: Email notifications enabled
- AEGIS-AZURE-105: Latest TLS version
- AEGIS-AZURE-106: Public network access disabled
- AEGIS-AZURE-107: Azure AD authentication
- AEGIS-AZURE-108: Private endpoint

**Projected after Phase 1+2:** 263 + 54 + 60 = 377 (still need +90)

### Phase 3: Medium-frequency gaps (+91 across 43 checks)
Target checks firing 2-4x. Need ~90 of 91 to surpass.

### Out of Scope
- Alibaba Cloud (CKV_ALI_*): 16 findings — Aegis has no Alibaba provider
- OCI (CKV_OCI_*): 6 findings — Aegis has no OCI provider
- Total out of scope: 22 findings

**Adjusted target:** 467 - 22 = 445 (excluding out-of-scope providers)
**Need:** 445 - 263 = 182 additional findings from AWS/Azure/GCP

## Rules Built (90 new rules, 497 → 587 total)

### Wave 1: High-Frequency Gaps
- **AWS RDS Cluster** (6 rules, AEGIS-AWS-631–636): audit logging, backtracking, copy tags, KMS CMK, Performance Insights, enhanced monitoring
- **Azure MSSQL** (8 rules, AEGIS-AZURE-101–108): auditing, retention, threat detection, email alerts, TLS, public access, AD auth, private endpoint
- **Azure App Service + Storage** (18 rules, AEGIS-AZURE-109–126): auth, certs, logging, FTP, HTTP2, managed identity, health check, storage hardening

### Wave 2: GCP Gap Closure
- **GCP** (22 rules, AEGIS-GCP-101–122): Cloud SQL flags, GKE hardening, node pool, compute, storage

### Wave 3: Long-Tail 1x Gaps
- **Azure AKS** (10 rules, AEGIS-AZURE-127–136): RBAC, network policy, private cluster, Key Vault provider, Defender, etc.
- **Azure App Service** (7 rules, AEGIS-AZURE-137–143): IP restrictions, CORS, backup, etc.
- **Azure Storage** (6 rules, AEGIS-AZURE-144–149): double encryption, replication, versioning, etc.
- **AWS Elasticsearch** (8 rules, AEGIS-AWS-637–644): HTTPS, dedicated master, encryption, logging, etc.
- **AWS Lambda** (5 rules, AEGIS-AWS-645–649): code signing, DLQ, EOL runtime, secrets in env, etc.

## Verification
- `go build ./...` ✅, `go vet` ✅, `gofmt` ✅
- Full test suite: all packages green ✅
- Quality gate: PASS ✅
- No duplicate/noise rules — each detects a real misconfiguration
