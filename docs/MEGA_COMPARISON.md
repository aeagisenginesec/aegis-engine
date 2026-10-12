# Aegis vs All IaC Scanners — AWS Detection Comparison

**Date:** 2026-10-11
**Environment:** Shared 2-CPU sandbox (results are environment-specific)
**Corpus:** vuln-200 (200 deliberately vulnerable resources, ~450 lines)

## Tools Tested

| Tool | Version | Type |
|------|---------|------|
| Aegis | dev (235 rules) | Go, single binary |
| Checkov | 3.3.26 | Python |
| Trivy | 0.74.0 | Go |
| tfsec | 1.28.x | Go (deprecated, merged into Trivy) |
| Terrascan | 1.19.9 | Go (Tenable) |
| Snyk IaC | 1.1307.4 | Node.js + cloud |

KICS was excluded — no binary release available for the current version.

## Findings on vuln-200 (higher = more detection)

| Tool | Findings | Time |
|------|---------:|-----:|
| **Aegis** | **451** | **~40ms** |
| tfsec | 531 | ~1.5s |
| Trivy | 495 | ~3.6s |
| Terrascan | 215 | ~5.2s |
| Checkov | 787 | ~9.9s |
| Snyk | 308 | ~15.7s |

## Findings on Compliant Fixture (lower = fewer false positives)

| Tool | Findings |
|------|---------:|
| **Trivy** | **0** |
| **Aegis** | **2** |
| tfsec | 6 |
| Snyk | 9 |
| Terrascan | 10 |
| Checkov | 27 |

## Speed Comparison (vs Aegis baseline)

| Tool | Time | Slower than Aegis |
|------|-----:|------------------:|
| **Aegis** | **~40ms** | **1x** |
| tfsec | ~1.5s | 37x |
| Trivy | ~3.6s | 90x |
| Terrascan | ~5.2s | 130x |
| Checkov | ~9.9s | 248x |
| Snyk | ~15.7s | 393x |

## Key Observations

1. **Aegis is the fastest by far** — 37x to 393x faster than every competitor.
2. **Checkov finds the most** (787) but also has the most false positives (27 on compliant).
3. **Trivy is the cleanest** (0 on compliant) with strong detection (495).
4. **Aegis balances both** — 451 findings with only 2 on compliant.
5. **tfsec is deprecated** — Aqua Security merged it into Trivy; included for completeness.
6. **Snyk is slowest** — cloud API round-trip adds significant latency.

## Honest Caveats

- Finding count ≠ true positives. One resource can trigger multiple checks.
- The vuln-200 labels are design targets, not a labeled ground-truth matrix.
- No precision/recall/F1 calculated — that requires per-vulnerability labeling.
- Single shared sandbox — results are environment-specific.
- tfsec/Terrascan/Trivy required HCL normalization (single-line blocks expanded).
