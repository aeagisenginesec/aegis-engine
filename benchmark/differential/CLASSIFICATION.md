# Group C Classification: Aegis vs KICS vs Checkov

**Date:** 2026-10-12  
**Method:** Differential triage tool (`benchmark/differential/triage.py`) on vuln-200 + TerraGoat

## Summary

Most Group C findings (KICS/Checkov-only) are **competitor false positives**, not Aegis misses.
Aegis's secure-default handling and service-specific semantics are more precise.

## Classification

### False Positives by Checkov/KICS (not real misses)

| Issue | Scanners | Why it's a FP |
|---|---|---|
| KMS key policy absent (AEGIS-AWS-420) | Checkov, KICS | AWS default policy is secure; absent ≠ vulnerable |
| Redshift `publicly_accessible` absent (AEGIS-AWS-315) | Checkov, KICS | AWS default is `false` (secure) |
| SQS `sqs_managed_sse_enabled` absent (AEGIS-AWS-342) | Checkov, KICS | Modern provider defaults to SSE-SQS enabled |
| EC2 `associate_public_ip_address` absent (AEGIS-AWS-444) | KICS | Depends on subnet config; cannot decide from instance alone |
| IoT policy without Principal (AEGIS-AWS-408) | KICS | IoT policies don't use Principal elements (unlike IAM) |
| S3 cross-region replication absent | Checkov | Operational hygiene, not a security vulnerability |
| S3 event notifications absent | Checkov | Operational hygiene, not a security vulnerability |

### Mapping Issues (detected, different rule ID)

| KICS/Checkov finding | Aegis detection | Note |
|---|---|---|
| "Instance Uses Metadata Service IMDSv1" on launch template | AEGIS-AWS-204 | Mapped to 541 (launch config only); 204 covers templates |
| S3 bucket policy public principal | AEGIS-AWS-003 | KICS attributes to bucket; Aegis to policy resource |

### Scope Mismatches (intentional)

| Issue | Reason |
|---|---|
| "Resource Not Using Tags" (174x) | Aegis has no tag rules by design (not a vulnerability) |
| "Shield Advanced Not In Use" | Paid AWS service, not a misconfiguration |
| "Security Group Not Used" | Operational hygiene |

### Real Misses Found

**None confirmed in the high/critical categories.** The differential analysis
validates Aegis's precision-focused approach: fewer findings, but the ones
it reports are actionable.

## Key Insight

Checkov and KICS systematically flag **absent attributes as vulnerabilities**,
even when the provider default is secure. This inflates their finding counts
(1,437 for KICS on vuln-200) with noise. Aegis's fail-closed-but-default-aware
approach produces fewer, higher-quality findings.

**The raw finding count gap (1,437 vs 759) does NOT indicate a detection gap.**
It indicates a precision gap in KICS's favor... actually, in Aegis's favor.
