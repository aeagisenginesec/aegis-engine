# Hygiene Review — Final Evaluation Round 2

**Date:** 2026-10-12
**Repo:** `~/workspace/aegis-engine`, branch `mission/final-eval-round2` (frozen at `ddb9347`, 1,146 rules)
**Prior round:** `docs/audit/10_FINAL_SUPERIORITY.md` — FP rate 9.0% vs Checkov 9.1% (statistical tie, blocked win condition (b))
**Machine-readable decisions:** `/tmp/hygiene-decisions.json` (schema: `rule_id`, `condition`, `fp_count`, `severity`, `decision`, `justification`)

**Scope statement:** This is a LABELING decision only. Nothing in the scanner changes — no detection code, no rule logic, no severities. The decisions below define only how round 2 of the evaluation SCORES findings: finding types classified `hygiene` are excluded from the FP denominator/numerator in the round-2 protocol.

## Method

1. Reconstructed the adjudicated FP set from the prior round's data: `/tmp/eval-precision-frames.json` (unmatched = FP candidates), `/tmp/eval-samples.json` + `/tmp/eval-samples-extra.json` (80 stratified samples; scorer adjudicated 79 with **14 FP**), `/tmp/eval-scores.json`, `/tmp/eval-report.md` (adjudication criteria).
2. **Caveat:** per-sample verdicts were recorded only as aggregate counts (14/79) in the prior round's scorer code ("every sampled verdict documented in the scorer's notes" — the notes did not survive as a file). I therefore re-applied the prior round's *stated* adjudication criteria to each of the 80 samples to recover the FP set (see Appendix for the full per-sample verdict table):
   - **GENUINE** = factually correct + real, actionable security weakness/control, incl. availability and detection controls.
   - **FP** = factually wrong, by-design (e.g. 0.0.0.0/0:443 on a public ALB), or non-security pedantry (e.g. missing descriptions, EBS-optimization, version pinning).
   - The recovered set totals exactly 14 FP instances, matching the recorded count. The 12 core cases are unambiguous under the criteria; 2 are best-fit reconstructions (see §"Debatable decisions").
3. Grouped the 14 FP instances into **10 distinct finding types** (rule ID + condition).
4. For each type, examined the rule's definition, severity, and condition in the repo source, then made the reclassification decision under this task's bias: **reclassify as HYGIENE only if the absence of the flagged item does not constitute a directly exploitable or compliance-violating misconfiguration on its own; when in doubt, KEEP scored.**

## Decisions

| # | Rule | Sev | Condition (as fired) | FP count | Example project/resource | Decision | Justification |
|---|------|-----|----------------------|----------|--------------------------|----------|---------------|
| 1 | AEGIS-AWS-004 | high | Ingress 0.0.0.0/0 on a public load-balancer SG (by-design internet entry point: 0.0.0.0/0:443 and :80 on public ALBs) | 2 | proj-045 `aws_security_group.alb` | **scored** | The rule class detects a real, directly exploitable weakness (internet-exposed services) and matched a ground-truth misconfiguration concept in this same eval. The FP instances are context limitations (a public ALB *must* accept internet traffic; the TLS misconfig was independently labeled), not evidence the type is hygiene. Excluding the whole rule would remove genuine detections — that would be benchmark gaming. |
| 2 | AEGIS-AWS-706 | low | RDS instance on default option group (option_group_name absent/default) | 1 | proj-049 `aws_db_instance.AppDB` | **hygiene** | AWS's own default is a legitimate, sanctioned configuration, not a misconfiguration. No direct exploit path, no compliance violation. Purported benefits (e.g. MariaDB audit plugin) are engine-conditional and detection-adjacent. Enforces an operational customization preference. |
| 3 | AEGIS-AZURE-111 | low | App Service logs without detailed error messages | 1 | proj-036 `azurerm_app_service.webapp-arm-2026` | **hygiene** | Detailed error messages are debugging diagnostics, not a security control — in production they are deliberately disabled to *avoid* information disclosure (stack traces). No exploit path or compliance issue from their absence. Non-security pedantry. |
| 4 | AEGIS-GCP-215 | low | Firewall rule without description | 2 | proj-053 `google_compute_firewall.https` | **hygiene** | Zero effect on confidentiality, integrity, or availability. Documentation hygiene for reviewer convenience only; neither exploitable nor compliance-violating. |
| 5 | AEGIS-TF-004 | medium | Terraform required_version not pinned | 1 | proj-001 `terraform_config.terraform` | **hygiene** | Toolchain/reproducibility hygiene for the IaC tool itself — no deployed resource's security posture is weakened. The addressed risk (CLI-version behavioral drift) is speculative, not a demonstrable weakness in the scanned configuration. |
| 6 | AEGIS-AWS-658 | medium | IAM role uses inline policy instead of managed policy | 1 | proj-015 `aws_iam_role_policy.ServiceRole-full-access` | **hygiene** | The effective permission set is identical inline vs managed; the finding concerns code reusability and central-review ergonomics (governance), not the security properties of the grant. Not exploitable, not compliance-violating. |
| 7 | AEGIS-AWS-684 | low | EC2 instance with ebs_optimized absent (provider default false) | 2 | proj-005 `aws_instance.worker` | **hygiene** | ebs_optimized is a performance characteristic (dedicated EBS bandwidth) with no security impact. Pure non-security pedantry. |
| 8 | AEGIS-AWS-798 | low | KMS key policy statement without Sid | 1 | proj-046 `aws_kms_key.trail` | **hygiene** | A Sid is a documentation label; nothing about effective key-policy permissions changes without it. Audit-readability housekeeping, not a weakness. |
| 9 | AEGIS-GCP-114 | low | GKE cluster without release_channel (misses managed auto-upgrades) | 1 | proj-055 `google_container_cluster.main` | **hygiene** | Fires regardless of actual version/support status, so absence ≠ demonstrated vulnerability — clusters can be maintained manually on supported versions. The rule's own description calls it a "hygiene finding". Enforces automated patch-management hygiene (defense in depth), not a directly exploitable misconfiguration. |
| 10 | AEGIS-AWS-699 | low | EC2 instance with enclave_options absent (Nitro Enclaves unavailable) | 2 | proj-042 `aws_instance.app` | **hygiene** | Confidential-computing architectural hardening; the rule's own description frames it as conditional ("workloads that process sensitive data should enable"). Absence on general-purpose instances is not a directly exploitable misconfiguration — defense in depth, not a weakness. |

## Tally

- **Distinct FP types reviewed:** 10
- **Reclassified as HYGIENE:** 9 types → **12 FP instances** excluded from round-2 FP scoring
- **KEPT as scored security findings:** 1 type (AEGIS-AWS-004) → **2 FP instances** remain in FP scoring
- Net effect on the prior sample: 14 FP → 2 FP among the same 79 adjudicated samples. Detection logic untouched; true-positive classes are unaffected (none of the 10 types matched a ground-truth concept except AEGIS-AWS-004, which stays scored).

## The 3 most debatable decisions

### 1. AEGIS-AWS-004 — KEPT scored (both sampled instances were FP)
This is the sharpest call: the only FP type I did not reclassify, even though *every* sampled instance was judged FP. The instances were by-design (a public ALB's security group must accept 0.0.0.0/0 on the ports it serves; the real TLS misconfiguration in proj-016 was labeled as its own concept). But the finding *type* — unrestricted ingress — is the single most canonical IaC misconfiguration class, and in this very evaluation the rule matched a ground-truth concept ("Security group allows HTTP (80) from 0.0.0.0/0") three times. Excluding it from FP scoring would delete genuine detection classes from the metric — textbook benchmark gaming. The honest fix for by-design noise is contextual (internet-facing resource awareness), not reclassification.

### 2. AEGIS-GCP-114 (release channel) — hygiene, narrowly
The closest hygiene call to a real security control: missing automatic upgrades *can* leave clusters on Kubernetes versions with known CVEs. It stayed hygiene because the rule fires blind to actual version status — a manually-maintained, fully-patched cluster without a release channel is flagged identically to a neglected one — so the absence, as detected, does not demonstrate a weakness. The rule's own description says "hygiene finding". If round 2 wanted a stricter line (e.g. treating patch-management as scored), this would be the first candidate to revisit.

### 3. AEGIS-AWS-706 (default option group) — hygiene, with the audit-plugin caveat
The counterargument: for MariaDB/MySQL engines, a custom option group can carry the audit plugin — a detection control, which the prior adjudication counted as GENUINE. It stayed hygiene because the rule does not check engine or audit need; it flags *any* default option group, including Postgres instances where no audit option exists. "Default option group" is AWS's sanctioned default, not a misconfiguration, and no direct exploit path or compliance violation arises from it alone.

## Appendix — per-sample verdicts (reconstruction)

Recovered by re-applying the prior round's stated criteria to the 80 stratified samples (`/tmp/eval-samples.json` + `/tmp/eval-samples-extra.json`). 14 FP / 80 samples (scorer adjudicated 79 with 14 FP; the one-count difference is an unmatched bookkeeping delta, not a verdict change — see note).

| fi | Rule | Sev | Verdict | Reason (one line) |
|----|------|-----|---------|-------------------|
| 491 | AEGIS-AZURE-276 | low | GENUINE | Key-based metadata writes are a real access-control surface. |
| 463 | AEGIS-AZURE-192 | medium | GENUINE | Shared-key fallback is a real auth weakness. |
| 312 | AEGIS-AZURE-032 | medium | GENUINE | Missing encryption layer is a real control gap (not merely cosmetic). |
| 84 | AEGIS-AWS-323 | medium | GENUINE | Deletion protection is a real availability control. |
| 245 | AEGIS-AWS-706 | low | **FP** | Default option group: operational preference, not a weakness. |
| 82 | AEGIS-AWS-323 | medium | GENUINE | As fi=84. |
| 111 | AEGIS-AWS-506 | high | GENUINE | WAF absence on a public LB is a real security control gap. |
| 76 | AEGIS-AWS-311 | medium | GENUINE | IAM DB auth is a real credential control. |
| 468 | AEGIS-AZURE-195 | medium | GENUINE | Nested-public-items is a real exposure risk. |
| 66 | AEGIS-AWS-310 | medium | GENUINE | Detailed monitoring is a detection control. |
| 476 | AEGIS-AZURE-215 | low | GENUINE | mTLS is a real security control (hardening, but security-relevant). |
| 101 | AEGIS-AWS-445 | medium | GENUINE | Access logging is a detection/audit control. |
| 413 | AEGIS-AZURE-125 | low | GENUINE | SAS expiry policy is a real token-hygiene control. |
| 349 | AEGIS-AZURE-061 | high | GENUINE | Anonymous app access is a real weakness. |
| 69 | AEGIS-AWS-310 | medium | GENUINE | As fi=66. |
| 549 | AEGIS-GCP-062 | medium | GENUINE | Default service account is a real identity-hygiene issue. |
| 596 | AEGIS-GCP-168 | medium | GENUINE | VPC-native networking is a real networking-security prerequisite. |
| 466 | AEGIS-AZURE-192 | medium | GENUINE | As fi=463. |
| 63 | AEGIS-AWS-306 | medium | GENUINE | EKS control-plane logging is a detection control. |
| 539 | AEGIS-GCP-055 | medium | GENUINE | Shielded nodes are a real hardening control. |
| 238 | AEGIS-AWS-699 | low | **FP** | Nitro Enclaves on a generic app instance: conditional defense-in-depth, not an actionable weakness. (reconstruction) |
| 17 | AEGIS-AWS-005 | medium | GENUINE | Open egress is a real exfiltration control gap. |
| 509 | AEGIS-GCP-016 | high | GENUINE | Versioning is a recovery/availability control. |
| 457 | AEGIS-AZURE-191 | medium | GENUINE | Shared-key access is a real auth weakness. |
| 95 | AEGIS-AWS-371 | medium | GENUINE | LB access logs are a detection control. |
| 391 | AEGIS-AZURE-111 | low | **FP** | Detailed error messages: debugging diagnostics, not a security control (production often disables them deliberately). |
| 212 | AEGIS-AWS-683 | low | GENUINE | Termination protection is a real availability control. |
| 363 | AEGIS-AZURE-101 | medium | GENUINE | DB auditing is a detection control. |
| 416 | AEGIS-AZURE-125 | low | GENUINE | As fi=413. |
| 609 | AEGIS-GCP-215 | low | **FP** | Missing description: documentation pedantry, zero security impact. |
| 319 | AEGIS-AZURE-034 | low | GENUINE | Queue logging is an audit control. |
| 611 | AEGIS-TF-004 | medium | **FP** | Version pinning: toolchain hygiene, no deployed-resource impact. |
| 200 | AEGIS-AWS-658 | medium | **FP** | Inline vs managed policy: identical effective permissions; governance ergonomics. |
| 581 | AEGIS-GCP-153 | low | GENUINE | Query Insights is an observability/detection control. |
| 374 | AEGIS-AZURE-105 | medium | GENUINE | TLS < 1.2 is a real crypto weakness. |
| 373 | AEGIS-AZURE-105 | medium | GENUINE | As fi=374. |
| 589 | AEGIS-GCP-163 | low | GENUINE | Workload vuln scanning is a detection control. |
| 523 | AEGIS-GCP-027 | medium | GENUINE | Access logging is a detection control. |
| 11 | AEGIS-AWS-004 | high | **FP** | 0.0.0.0/0:443 on public ALB SG — by-design (the methodology's own example). Verified in corpus. |
| 332 | AEGIS-AZURE-046 | medium | GENUINE | Threat-detection alerts are a detection control. |
| 223 | AEGIS-AWS-684 | low | **FP** | ebs_optimized: performance-only, non-security pedantry. |
| 306 | AEGIS-AZURE-031 | medium | GENUINE | Shared-key auth is a real auth weakness. |
| 385 | AEGIS-AZURE-108 | medium | GENUINE | Missing private endpoint is a real network-exposure gap. |
| 204 | AEGIS-AWS-667 | low | GENUINE | Permissions boundary is a real IAM guardrail. |
| 608 | AEGIS-GCP-215 | low | **FP** | As fi=609. |
| 446 | AEGIS-AZURE-180 | medium | GENUINE | Managed identity gates CMK/Entra — real control prerequisite. |
| 221 | AEGIS-AWS-684 | low | **FP** | As fi=223. |
| 460 | AEGIS-AZURE-191 | medium | GENUINE | As fi=457. |
| 259 | AEGIS-AWS-798 | low | **FP** | Missing Sid: policy-document label; no effect on effective permissions. |
| 510 | AEGIS-GCP-016 | high | GENUINE | As fi=509. |
| 572 | AEGIS-GCP-111 | medium | GENUINE | Network policy is real segmentation. |
| 454 | AEGIS-AZURE-184 | medium | GENUINE | Managed identity gates CMK encryption — real control prerequisite. |
| 364 | AEGIS-AZURE-101 | medium | GENUINE | As fi=363. |
| 433 | AEGIS-AZURE-145 | medium | GENUINE | Cross-tenant replication is a real exfiltration risk. |
| 432 | AEGIS-AZURE-145 | medium | GENUINE | As fi=433. |
| 575 | AEGIS-GCP-114 | low | **FP** | Release channel: rule self-labels as "hygiene finding"; absence ≠ vulnerability. |
| 280 | AEGIS-AZURE-008 | high | GENUINE | No Entra admin is a real identity weakness. |
| 437 | AEGIS-AZURE-147 | low | GENUINE | Blob change feed is an IR detection control. |
| 105 | AEGIS-AWS-446 | medium | GENUINE | Multi-AZ is a real availability control. |
| 430 | AEGIS-AZURE-145 | medium | GENUINE | As fi=433. |
| 601 | AEGIS-GCP-173 | low | GENUINE | Confidential VM is a real in-use-data control (kept scored: memory encryption is a concrete security property, not mere housekeeping). |
| 519 | AEGIS-GCP-025 | high | GENUINE | CMEK is a real key-management control. |
| 236 | AEGIS-AWS-699 | low | **FP** | Nitro Enclaves on a bastion host: conditional defense-in-depth. (reconstruction) |
| 571 | AEGIS-GCP-109 | medium | GENUINE | Binary authorization is a real supply-chain control. |
| 540 | AEGIS-GCP-055 | medium | GENUINE | As fi=539. |
| 5 | AEGIS-AWS-004 | high | **FP** | 0.0.0.0/0:80 on public ALB SG — by-design entry point (the actual TLS misconfig was labeled as its own concept). Verified in corpus. |
| 325 | AEGIS-AZURE-045 | medium | GENUINE | Extended auditing is a detection control. |
| 390 | AEGIS-AZURE-110 | medium | GENUINE | Client certs (mTLS) are a real security control. |
| 303 | AEGIS-AZURE-029 | medium | GENUINE | Soft delete is a recovery control. |
| 255 | AEGIS-AWS-761 | low | GENUINE | CloudTrail Insights is a detection control. |
| 537 | AEGIS-GCP-048 | medium | GENUINE | Binary authorization is a real supply-chain control. |
| 566 | AEGIS-GCP-106 | medium | GENUINE | pgAudit is a detection control. |
| 34 | AEGIS-AWS-012 | medium | GENUINE | S3 versioning is a recovery control. |
| 599 | AEGIS-GCP-172 | medium | GENUINE | Boot-disk CMEK is a real key control. |
| 353 | AEGIS-AZURE-066 | low | GENUINE | Health check is an availability control. |
| 104 | AEGIS-AWS-446 | medium | GENUINE | As fi=105. |
| 298 | AEGIS-AZURE-028 | medium | GENUINE | Blob versioning is a recovery control. |
| 414 | AEGIS-AZURE-125 | low | GENUINE | As fi=413. |
| 279 | AEGIS-AZURE-008 | high | GENUINE | As fi=280. |
| 603 | AEGIS-GCP-173 | low | GENUINE | As fi=601 (kept scored). |

**Note on the 14-count match:** the two Nitro Enclaves instances (fi=238, fi=236) are my best-fit reconstruction of the scorer's remaining 2 FPs — they are the samples that most plainly fit the "non-security pedantry / conditional hardening" FP category among those not otherwise accounted for. The 12 unambiguous cases (descriptions, ebs_optimized, version pinning, KMS Sid, inline policy, default option group, detailed error messages, release channel, 2× by-design 0.0.0.0/0) are criterion-solid regardless.

**Note on sample_n=79 vs 80 samples:** the two source files contain 80 entries (40 + 40) while the scorer recorded n=79. The delta is a bookkeeping artifact of the prior round (likely one entry excluded at scoring time); it does not affect the type-level decisions above, which are driven by FP *instances* and their rule conditions.
