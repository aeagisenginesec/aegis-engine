# Corpus-v2: Continuously Expanding AWS Test Corpus

**Version:** v2 (2026-10-12) | **Projects:** 200 (140 vulnerable, 60 secure) | **Aegis rules:** 698

## Why v2 exists

Corpus v1 (100 projects) was used to tune rules. Continuing to tune against the
same projects risks overfitting — good scores that don't generalize. Corpus-v2
uses entirely new templates (different seed, different project structures) and
a locked held-out split that rule authors must not tune against.

## Methodology

### Generation
- Three independent template builders produced `gen/partA.py` (IAM/secrets/exposure),
  `gen/partB.py` (encryption/logging/network), `gen/partC.py` (edge cases + secure).
- Every template was scan-verified: each expected finding confirmed firing via
  real `aegis scan --format=json` before acceptance.
- Templates harden everything except the vulnerability under test (silencer
  snippets), isolating one issue family per project.
- No templates reused from v1; preferred rules outside v1's 59-rule coverage.
- No real secrets in any fixture (fake placeholders only, verified by byte inspection).

### Coverage areas
| Area | Projects | Example rules |
|---|---|---|
| IAM privilege escalation | 25 | 333, 630, 553, 554, 406, 407, 562, 399 |
| Secret leakage | 15 | 535, 536, 537, 539, 307, 514, 337 |
| Public exposure chains | 20 | 005, 328, 329, 405, 413, 427, 442 |
| Encryption gaps | 25 | 515–520, 351, 352, 354, 359, 634, 301, 357, 432 |
| Logging blind spots | 20 | 010, 568, 209, 306, 308, 327, 332, 371, 348, 605–611 |
| Network misconfigurations | 25 | 396, 328, 331, 201, 325, 326, 329, 506–513, 556, 557 |
| Edge cases | 10 | nested modules, cross-file refs, jsonencode, for_each, locals indirection, data sources, count |
| Secure (hardened) | 60 | verified 0 medium+ findings |

### Held-out split
- **Dev:** 150 projects (`projects/`, `manifest.json`) — visible.
- **Held-out:** 50 projects (`heldout/`) — 35 vulnerable + 15 secure, selected by
  secret-seeded stratified shuffle. Manifest chmod 600, sha256 recorded in `SPLIT.md`.
- **known_gap (RESOLVED 2026-10-12):** 2 projects documented genuine scanner
  limitations (dynamic-block expansion, policy-document data sources).
  Both gaps are now fixed: dynamic blocks expand after variable resolution
  with explicit diagnostics for unresolvable for_each; data
  `aws_iam_policy_document` references resolve to constructed policy JSON.
  Their `known_gap` flags are cleared in manifest.json. Forced into dev,
  excluded from recall denominators, reported separately — never silently
  dropped.

### Scoring
`score.py` runs Aegis per-project and reports:
- Project-level precision / recall / F1, false-positive rate
- Finding-level per-severity recall (critical/high/medium/low)
- Dev and held-out separately
- **Gate:** exit 1 if held-out F1 < 0.90

## Baseline scores (Aegis 698 rules)

| Split | Precision | Recall | F1 | FP rate | Crit recall | High recall | Med recall |
|---|---|---|---|---|---|---|---|
| Dev (150) | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 1.000 |
| Held-out (50) | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 | 1.000 | 1.000 |

Avg scan time: ~56 ms/project. Held-out gate: PASS.

## Comparison (context)

| Split | Tool | Vuln detection (med+) | Secure FP rate | Avg ms/project |
|---|---|---|---|---|
| Dev (150) | Aegis | 1.000 (103/103) | 0.000 (0/45) | ~55 |
| Dev (150) | Checkov 3.3.26 | 0.816 (84/103) | 0.844 (38/45) | ~113 |
| Dev (150) | KICS 2.1.20 | 0.476 (49/103) | 0.711 (32/45) | ~593 |
| Held-out (50) | Aegis | 1.000 (35/35) | 0.000 (0/15) | ~60 |
| Held-out (50) | Checkov 3.3.26 | 0.829 (29/35) | 0.867 (13/15) | ~247 |
| Held-out (50) | KICS 2.1.20 | 0.400 (14/35) | 0.800 (12/15) | ~1291 |

Methodology notes: KICS medium+ = CRITICAL/HIGH/MEDIUM; Checkov's JSON severity is
null so all failed checks count (Checkov numbers are upper bounds). Project-level
detection = ≥1 finding on the project. **Important caveat:** the corpus labels are
Aegis-centric (each fixture isolates an Aegis-detectable issue), so rival tools'
lower detection rates partly reflect scope differences, not pure accuracy gaps.
Notably, KICS flagged all 103 dev vulnerable projects at *some* severity — but for
54 of them only LOW/INFO hygiene findings (e.g. "Resource Not Using Tags") on
genuinely high-severity misconfigurations, a severity-calibration gap worth noting.

## Manual verification
- 100% of templates scan-verified by builders at creation.
- 20% random spot-check (40 projects: 28 vuln + 12 secure) manually reviewed:
  labels semantically match the Terraform content; secure projects genuinely hardened.
- Fake-secret placeholders confirmed by raw byte inspection (no real credentials).

## Expanding the corpus
1. Add new templates to `gen/` (follow the existing schema).
2. Re-run `assemble.py` (reuses the held-out seed in `heldout/.seed`).
3. Re-run `score.py`; the held-out gate must stay green.
4. Never add held-out projects to dev or tune against them.
