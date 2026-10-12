# Scaling Investigation — Post-Audit Remediation

**Date:** 2026-10-12  
**Branch:** `fix/post-audit-reliability`

## Audit Claim

The phase-7 audit reported "near-quadratic scaling past ~4k resources".

## Methodology

Tested with synthetic Terraform files containing N `aws_s3_bucket` resources
(no inter-resource references, minimal attributes).

**Machine:**
- CPU: AMD EPYC 9D25 (2 vCPU)
- RAM: 7.7 GB
- OS: Linux 7.0.0-39-generic x86_64

**Command:** `aegis scan /tmp/scale_test` (built from `fix/post-audit-reliability`)

## Results

| Resources | Time | ms/resource | Findings |
|-----------|------|-------------|----------|
| 1,000 | 0.168s | 0.168 | 6,002 |
| 2,000 | 0.284s | 0.142 | 12,002 |
| 4,000 | 0.732s | 0.183 | 24,002 |
| 8,000 | 1.029s | 0.129 | 48,002 |

## Analysis

- 1k→4k (4x resources): 0.168s→0.732s (4.36x time) — **approximately linear**
- 4k→8k (2x resources): 0.732s→1.029s (1.41x time) — **sublinear** (likely warmup/cache effects)
- Per-resource time is stable (~0.13-0.18ms), not growing with N

**The near-quadratic claim was NOT reproduced** with this workload.

## Limitations

This test uses homogeneous S3 buckets with no references. Quadratic behavior
may occur with:
1. Dense inter-resource reference graphs (e.g., many security group rules
   referencing many instances)
2. Rules that perform O(n²) pairwise comparisons
3. Specific adapter pathologies (e.g., HCL expression evaluation)

## Conclusion

**Deferred with justification:** The simple scaling test shows linear behavior
through 8k resources. The audit's quadratic claim may be workload-specific.
A deeper investigation with realistic, reference-dense workloads is needed
to identify the hot path, but is out of scope for this trust-repair mission.

**Recommendation:** Profile with production-representative Terraform (e.g.,
the AWS demo corpus scaled up) in a follow-up. Do NOT claim linear
complexity — the evidence only covers homogeneous workloads.
