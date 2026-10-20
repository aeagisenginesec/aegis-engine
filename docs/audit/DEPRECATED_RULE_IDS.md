# Deprecated Rule IDs — Post-Audit Deduplication

**Date:** 2026-10-12  
**Branch:** `fix/post-audit-reliability`  
**Baseline:** `d9eea30`

This document maps the 48 rule IDs removed during post-audit deduplication to their canonical replacements. The removed rules were exact semantic duplicates, strict subsets, or false-positive-prone single-form checks superseded by comprehensive cross-form rules.

## Multi-cloud quality audit (2026-10-14) — 9 removed

Found by the Aegis Multi-Cloud Finding Quality Audit (report 15) on a
multi-cloud fixture: the legacy Azure SQL rules check only the inline-block
form and fire false positives on servers configured via the standalone
resource form (which the comprehensive CheckAll rules 101/106/107 handle
correctly). AZR-004/048 are exact duplicates of each other; 047/225 are
exact duplicates of each other; 025 is a strict subset of 105; 063 is an
exact duplicate of 018 with a looser (Contains) match. None of these were
removed to reduce finding counts — each removal fixes a proven false
positive or an exact-duplicate check. AEGIS-AZURE-206's canonical pointer
was also updated transitively (206 → 025 → now 105).

| Removed ID | Canonical ID | Reason |
|------------|--------------|--------|
| AEGIS-AZR-004 | AEGIS-AZURE-106 | Exact duplicate of 048; subset of 106 (106 also fires on absent, provider default true) |
| AEGIS-AZURE-008 | AEGIS-AZURE-107 | FP-prone: fires when standalone azuread_administrator resource exists; 107 checks both forms |
| AEGIS-AZURE-009 | AEGIS-AZURE-101 | FP-prone: fires when standalone auditing-policy resource exists; 101 checks both forms |
| AEGIS-AZURE-025 | AEGIS-AZURE-105 | Subset: 105 also covers absent minimum_tls_version (default below 1.2) |
| AEGIS-AZURE-045 | AEGIS-AZURE-101 | Same check as 009 (Medium); FP-prone on standalone form |
| AEGIS-AZURE-047 | AEGIS-AZURE-107 | Same check as 008 (Medium); FP-prone on standalone form |
| AEGIS-AZURE-048 | AEGIS-AZURE-106 | Exact duplicate of AZR-004; subset of 106 |
| AEGIS-AZURE-225 | AEGIS-AZURE-107 | Exact duplicate of 047 ("Entra ID" is the Azure AD rename); FP-prone on standalone form |
| AEGIS-GCP-063 | AEGIS-GCP-018 | Exact duplicate: 018's exact/suffix scope match subsumes 063's Contains match |

## Follow-up to the multi-cloud quality audit (2026-10-14) — 1 removed

Found by the per-finding re-trace of all 122 remaining findings (report 15
addendum): AEGIS-GCP-122 fires on the identical condition as AEGIS-GCP-032
(any `public_access_prevention` ≠ `"enforced"` on `google_storage_bucket`)
but at High severity versus 032's Medium — a double-reported finding with an
inconsistent severity. 032 (Medium) is kept as canonical; the hardening
control is defense-in-depth, not an active exposure.

| Removed ID | Canonical ID | Reason |
|------------|--------------|--------|
| AEGIS-GCP-122 | AEGIS-GCP-032 | Exact duplicate of 032 with inconsistent severity (High vs Medium); 032 kept |

## Post-audit deduplication (2026-10-12) — 39 removed

**Date:** 2026-10-12  
**Branch:** `fix/post-audit-reliability`  
**Baseline:** `d9eea30`

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

## R4 FP-family deduplication — Sprint 2 (2026-10-20)

Found by the Sprint-2 false-positive-family hunt over the R4 blind-eval
sweep (report 25): later "round" files re-implemented checks that already
existed, so one weakness was reported two or three times per resource.
Each removal below was verified at the mechanism level (firing truth
tables compared in code, not just on the corpus) and the R4 rescore
after each batch must keep TP = 136 / FN = 0.

| Removed ID | Canonical ID | Reason |
|------------|--------------|--------|
| AEGIS-AZURE-007 | AEGIS-AZURE-187 | Strict subset: 007 fires only on network_acls absent or default_action = "Allow"; 187 fires on absent or any default_action ≠ "Deny" (all blocks) |
| AEGIS-AZURE-027 | AEGIS-AZURE-121 | Strict subset: 027 is 121 without the absent case (min_tls_version, default TLS1_0) |
| AEGIS-AZURE-119 | AEGIS-AZURE-122 | Subset + FP-prone: with allow_nested_items_to_be_public absent, 119 is identical to 122; its nested-present path fires even when allow_blob_public_access = false (no exposure possible — the bug class fixed in AEGIS-AZURE-195 during R5) |
| AEGIS-AZURE-191 | AEGIS-AZURE-031 | Exact duplicate: same attribute (shared_access_key_enabled), same truth table, same severity |
| AEGIS-AZURE-075 | AEGIS-AZURE-229 | Strict subset: 229 also fires on empty authorized_ip_ranges and scans all api_server_access_profile blocks; 075 checked only the first block |
| AEGIS-AZURE-230 | AEGIS-AZURE-128 | Strict subset: 230 fires only when the AAD RBAC block is absent; 128 also fires when the block is present with managed absent/false |
| AEGIS-AZURE-245 | AEGIS-AZURE-127 | Exact duplicate: same attribute (local_account_disabled), same truth table (absent/false fires, true quiet) |
| AEGIS-AWS-540 | AEGIS-AWS-311 | Exact duplicate on mysql/postgres instances (identical firing sets in the R4 sweep) with inconsistent severity (High vs Medium); 540's engine scoping was ported into 311, which also no longer fires on engines without IAM database authentication (oracle/sqlserver — a latent factual FP) |
| AEGIS-AWS-547 | AEGIS-AWS-308 | Exact duplicate: same tracing_config truth table on aws_lambda_function |
| AEGIS-AWS-840 | AEGIS-AWS-329 | Strict subset: 329 matches protocol case-insensitively (EqualFold) and also covers block-absent HTTPS health-check configs; 840 was case-sensitive |
| AEGIS-AWS-418 | AEGIS-AWS-523 | Subset: three rules reported one missing OpenSearch control; 523's truth table is the union of 418 and 811 on advanced_security_options |
| AEGIS-AWS-811 | AEGIS-AWS-523 | Exact duplicate of 523 (advanced_security_options) with inconsistent severity (High vs Medium) |
| AEGIS-AWS-812 | AEGIS-AWS-623 | Duplicate on aws_opensearch_domain (log_publishing_options absent); 623 also covers aws_elasticsearch_domain |
