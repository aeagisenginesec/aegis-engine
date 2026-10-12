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
- **known_gap:** 2 projects document genuine scanner limitations (dynamic-block
  expansion, policy-document data sources). Forced into dev, excluded from recall
  denominators, reported separately — never silently dropped.

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

| Split | Tool | Vuln detection rate | Secure FP rate | Avg ms/project |
|---|---|---|---|---|
| _to be filled from score.py comparison run_ | | | | |

Methodology notes: KICS counts HIGH/MEDIUM findings; Checkov's JSON severity is
null so all failed checks count (Checkov numbers are upper bounds). Project-level
detection = ≥1 finding on the project.

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
