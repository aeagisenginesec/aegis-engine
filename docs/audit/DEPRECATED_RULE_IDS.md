# Deprecated Rule IDs — Post-Audit Deduplication

**Date:** 2026-10-12  
**Branch:** `fix/post-audit-reliability`  
**Baseline:** `d9eea30`

This document maps the 39 rule IDs removed during post-audit deduplication to their canonical replacements. The removed rules were exact semantic duplicates or strict subsets of the canonical rules.

## AWS (12 removed)

| Removed ID | Canonical ID | Reason |
|------------|--------------|--------|
| AEGIS-AWS-621 | AEGIS-AWS-316 | Exact duplicate: Redshift logging |
| AEGIS-AWS-550 | AEGIS-AWS-320 | Exact duplicate: ElastiCache transit encryption |
| AEGIS-AWS-549 | AEGIS-AWS-321 | Exact duplicate: ElastiCache at-rest encryption |
| AEGIS-AWS-715 | AEGIS-AWS-321 | Exact duplicate: ElastiCache at-rest encryption |
| AEGIS-AWS-830 | AEGIS-AWS-332 | Dead rule: typo'd type `aws_api_gatewayv2_stage` (never fires) |
| AEGIS-AWS-831 | AEGIS-AWS-404 | Dead rule: typo'd type `aws_api_gatewayv2_route` (never fires) |
| AEGIS-AWS-782 | AEGIS-AWS-420 | Exact duplicate: KMS public principal |
| AEGIS-AWS-815 | AEGIS-AWS-430 | Exact duplicate: DocDB deletion protection |
| AEGIS-AWS-719 | AEGIS-AWS-440 | Exact duplicate: Neptune deletion protection |
| AEGIS-AWS-701 | AEGIS-AWS-605 | Exact duplicate: RDS enhanced monitoring |
| AEGIS-AWS-718 | AEGIS-AWS-608 | Exact duplicate: RDS Performance Insights |
| AEGIS-AWS-752 | AEGIS-AWS-625 | Exact duplicate: CloudFront logging |

## Azure (22 removed)

| Removed ID | Canonical ID | Reason |
|------------|--------------|--------|
| AEGIS-AZURE-036 | AEGIS-AZR-005 | Exact duplicate: Key Vault purge protection |
| AEGIS-AZURE-213 | AEGIS-AZURE-012 | Exact duplicate: App Service TLS |
| AEGIS-AZURE-312 | AEGIS-AZURE-020 | Exact duplicate: Redis TLS |
| AEGIS-AZURE-206 | AEGIS-AZURE-025 | Exact duplicate: SQL Server TLS |
| AEGIS-AZURE-146 | AEGIS-AZURE-028 | Exact duplicate: Storage blob versioning |
| AEGIS-AZURE-203 | AEGIS-AZURE-028 | Exact duplicate: Storage blob versioning |
| AEGIS-AZURE-126 | AEGIS-AZURE-029 | Exact duplicate: Storage blob soft delete |
| AEGIS-AZURE-193 | AEGIS-AZURE-029 | Exact duplicate: Storage blob soft delete |
| AEGIS-AZURE-198 | AEGIS-AZURE-030 | Exact duplicate: Storage container soft delete |
| AEGIS-AZURE-123 | AEGIS-AZURE-031 | Exact duplicate: Storage shared key |
| AEGIS-AZURE-144 | AEGIS-AZURE-032 | Exact duplicate: Storage infra encryption |
| AEGIS-AZURE-196 | AEGIS-AZURE-032 | Exact duplicate: Storage infra encryption |
| AEGIS-AZURE-120 | AEGIS-AZURE-034 | Exact duplicate: Storage queue logging |
| AEGIS-AZURE-188 | AEGIS-AZURE-038 | Exact duplicate: Key Vault RBAC |
| AEGIS-AZURE-190 | AEGIS-AZURE-040 | Partial: 190's empty-string check ported to 040 |
| AEGIS-AZURE-202 | AEGIS-AZURE-042 | Partial: 202's logic kept via 042 (stricter) |
| AEGIS-AZURE-243 | AEGIS-AZURE-057 | Partial: 243's enable-check ported to 057 |
| AEGIS-AZURE-109 | AEGIS-AZURE-061 | Exact duplicate: App Service auth |
| AEGIS-AZURE-117 | AEGIS-AZURE-066 | Exact duplicate: App Service health check |
| AEGIS-AZURE-234 | AEGIS-AZURE-136 | Exact duplicate: AKS OIDC issuer |
| AEGIS-AZURE-298 | AEGIS-AZURE-155 | Exact duplicate: Data Factory public net |
| AEGIS-AZURE-178 | AEGIS-AZURE-062 | Subset: 178 (app_service only) merged into 062 (3 types) |

## GCP (5 removed)

| Removed ID | Canonical ID | Reason |
|------------|--------------|--------|
| AEGIS-GCP-121 | AEGIS-GCP-005 | Partial: 121's absent-handling ported to 005 |
| AEGIS-GCP-110 | AEGIS-GCP-009 | Exact duplicate: GKE legacy ABAC |
| AEGIS-GCP-112 | AEGIS-GCP-011 | Partial: 112's enable_private_nodes check ported to 011 |
| AEGIS-GCP-118 | AEGIS-GCP-057 | Exact duplicate: Compute IP forwarding |
| AEGIS-GCP-119 | AEGIS-GCP-058 | Exact duplicate: Compute serial port |

## Severity Changes

Per the "higher wins" policy, the following canonical rules had their severity increased:

- AEGIS-AWS-320: Medium → High
- AEGIS-AWS-321: Medium → High
- AEGIS-AZR-005: Medium → High
- AEGIS-AZURE-020: Medium → High
- AEGIS-AZURE-032: Low → Medium
- AEGIS-AZURE-155: Medium → High

## API Compatibility

The removed rule IDs will no longer appear in scan output. Suppressions referencing removed IDs should be migrated to the canonical IDs. SARIF fingerprints will change for affected rules (new rule ID in the fingerprint).

## Rule Count

- Before: 1,185 rules
- After: 1,146 rules
- Removed: 39 duplicates
