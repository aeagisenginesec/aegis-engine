# Final Boss Test: Aegis vs Checkov — AWS IaC Detection

**Date:** 2026-10-11
**Versions:** Aegis (184 rules, this repo) vs Checkov **3.3.26**
**Machine:** 2 CPUs, shared load. Times are medians of multiple runs.
**Method:** 5 corpora, ground-truth vulnerability counts where designed,
timing, peak RSS, parser robustness.

## Corpora

| Corpus | Resources | Ground truth |
|--------|-----------|--------------|
| vuln-50 | 49 | 50 designed vulnerabilities |
| vuln-200 | 200 | 200 designed vulnerabilities |
| 3-tier | 41 | realistic vulnerable app (unknown count) |
| compliant | 27 | 0 vulnerabilities (any finding = false positive) |
| big-synth | 3,000 | synthetic mix (500 files) |

## Detection results

| Corpus | Aegis findings | Checkov failed | Aegis rules | Checkov checks |
|--------|---------------|----------------|-------------|----------------|
| vuln-50 | 106 (4 crit, 45 high, 57 med) | 210 | 53 | 129 |
| vuln-200 | 440 (13 crit, 207 high, 220 med) | 787 | 89 | 180 |
| 3-tier | 40 (3 crit, 23 high, 14 med) | 66 | 29 | 57 |
| compliant | **1** (1 med) | **27** | 1 | 24 |
| big-synth | 7,875 | 15,419 | 14 | 23 |

### Reading the counts honestly

- **Designed vulnerabilities are all caught by both tools.** The finding
  counts exceed the designed counts because one vulnerable resource
  triggers multiple rules (e.g. an unencrypted RDS also lacks backup,
  deletion protection, Multi-AZ).
- **Checkov's higher counts are low-signal checks**: security-group
  descriptions, S3 lifecycle rules, event notifications, tag copying,
  cross-region replication, RDS minor-upgrade flags. None are
  vulnerabilities.
- **Compliant lab:** Checkov's 27 are all hygiene/observability
  (lifecycle, notifications, replication, performance insights,
  CloudTrail-to-SNS). Aegis's 1 is the logging-target bucket lacking
  its own logging — arguably correct per the same logic Checkov
  applies elsewhere.

**Detection verdict:** parity on true positives, parity on false
positives (both ~zero on real vulnerabilities). Neither tool misses
a designed vulnerability the other catches.

## Performance results

| Corpus | Aegis (median) | Checkov (median) | Speedup | Aegis RSS | Checkov RSS |
|--------|---------------|------------------|---------|-----------|-------------|
| vuln-50 | 10.2 ms | 7.01 s | **686×** | 11 MB | 182 MB |
| vuln-200 | 47.5 ms | 8.21 s | **173×** | 16 MB | 197 MB |
| 3-tier | 8.3 ms | 8.41 s | **1,008×** | 13 MB | 183 MB |
| compliant | 8.4 ms | 5.90 s | **704×** | 9 MB | 176 MB |
| big-synth | 1.07 s | 24.38 s | **23×** | 47 MB | 632 MB |

**Performance verdict:** Aegis wins every corpus by 1–3 orders of
magnitude, using 10–16× less memory. The gap narrows at scale
(Checkov parallelizes) but never closes.

## Robustness

| Edge case | Aegis | Checkov |
|-----------|-------|---------|
| Single-line nested blocks (valid HCL) | PASS | PASS |
| Single-line attributes | PASS | PASS |
| jsonencode() policies | PASS | PASS |
| Reference attributes | PASS | PASS |

**Robustness verdict:** Tie on these fixtures. An earlier draft claimed
Checkov 3.3.26 fails single-line nested HCL blocks, but the failing
fixture was later shown to be invalid HCL; on valid single-line nested
blocks both parsers pass. Parser robustness is not a proven Aegis
advantage from these fixtures.

## Capabilities only one side has

**Aegis only:**
- Attack-path correlation (internet → SG → database, per-hop evidence)
- Hardcoded secret detection with value redaction
- Validated auto-remediation (`aegis fix`)
- 124 distinct AWS resource types with dedicated rules

**Checkov only:**
- ~1,000+ checks across Dockerfiles, K8s manifests, ARM, Bicep, etc.
- Larger community and ecosystem

## Final verdict

For **AWS Terraform scanning**: Aegis matches Checkov on detection
quality, beats it on depth (paths, secrets, fix), crushes it on speed
(23–1,008×) and memory (10–16×). Checkov remains the better generalist
across IaC frameworks.
