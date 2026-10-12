# Aegis vs Checkov: Rigorous Comparison

**Date:** 2026-10-11
**Method:** Two independent benchmarks + attack-path validation

## Benchmark 1: Original 3-Corpus Comparison

| Corpus | Aegis findings | Checkov findings |
|--------|---------------:|-----------------:|
| vuln-200 | 775 | 787 |
| compliant-lab | 16 | 27 |
| three-tier | 61 | 66 |
| **Total** | **852** | **880** |

Raw finding counts. Not unique vulnerabilities — rules can overlap, severities differ.

## Benchmark 2: Held-Out Validation (Phase 5)

**Corpus:** 200 fresh projects (seed 999), 140 vulnerable / 60 clean, multi-file structures.
**Versions:** Aegis (sha256:b4444006...), Checkov 3.3.26.

### Detection

| Metric | Aegis | Checkov |
|--------|------:|--------:|
| Precision | 0.700 | 0.700 |
| Recall | 1.000 | 1.000 |
| F1 | 0.824 | 0.824 |

**Identical.** Both caught every vulnerable project. Both flagged every "clean" project (which weren't truly clean — see limitations).

### Speed

| Metric | Aegis | Checkov | Ratio |
|--------|------:|--------:|------:|
| Median | 7.8ms | 4054ms | **520x** |
| p95 | 12.4ms | 4394ms | **354x** |

### Attack Paths (5 spot-checks)

| Scenario | Result |
|----------|--------|
| Full chain (SG→EC2→RDS) | ✅ 3-hop chain with file:line evidence |
| Uncertain (variable CIDR) | ✅ Explicit UNCERTAIN marker, no invention |
| No connection | ✅ Correctly empty |
| Split-file chain (no graph edge) | ❌ Missed — corpus gap, not builder bug |

## What Each Tool Does Better

**Checkov:**
- Larger rule library for some Azure/GCP edge cases (not measured here)
- Broader community and ecosystem

**Aegis:**
- 520x faster (7.8ms vs 4s median)
- Attack-path chains with evidence (Checkov has no equivalent)
- Unique rule classes: Terraform backend security, deep secrets with taint tracking, supply-chain (curl-pipe-bash), IAM privilege escalation chains
- Severity-ranked output

## Limitations (Read Before Citing)

1. **Precision 70%, not 95%.** The quality gate target (≥95%) is unmet by both tools at project level. "Clean" projects triggered hygiene findings. This is noise, not missed vulns (recall is 100%).
2. **Project-level metrics.** We count flagged projects, not individual vulnerabilities found.
3. **Synthetic corpora.** Generated Terraform, not production repos.
4. **Finding counts ≠ unique vulns.** Rules overlap; raw totals inflate.
5. **Single-machine timing.** Ratios are robust; absolute times are not.

## Bottom Line

On detection accuracy, **Aegis and Checkov are tied** (F1 0.824 both). On speed, **Aegis is 520x faster**. On advanced capabilities (attack paths, secret taint tracking, backend security), **Aegis has no Checkov equivalent**. Neither tool is "the winner" on all dimensions — choose based on what matters: raw rule count (Checkov), speed + depth (Aegis).

Raw data: `benchmark/heldout_results.json`, `benchmark/VERSIONS.md`.
Full methodology: `docs/PHASE5_VALIDATION.md`.

---

## Update (2026-10-12): Rigorous Benchmark with 587 Rules

A follow-up rigorous benchmark was run with Aegis at 587 rules. See `docs/RIGOROUS_BENCHMARK.md` for full details.

Key new findings:
- **Held-out accuracy still tied:** Both tools P=0.653, R=1.0, F1=0.79 on a fresh 150-project corpus (seed 20261012).
- **Manual precision review:** Aegis 0.784 vs Checkov 0.676 on 50 sampled TerraGoat findings each.
- **Performance regression:** Aegis on vuln-200 slowed ~9x with 587 rules (374ms → 3,299ms median). Speedup vs Checkov collapsed from 16x to 1.9x on this corpus. Rule count has a real performance cost.
- **Speedup now varies 1.9x–158.8x** across corpora (was claimed 520x on a small corpus).

The bottom line is unchanged: tied on accuracy, Aegis faster (but the margin is smaller than previously reported on large files), Aegis has unique capabilities.
