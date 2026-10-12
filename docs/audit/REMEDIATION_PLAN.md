# Post-Audit Remediation — Defect Inventory & Classification

**Branch:** `fix/post-audit-reliability` (from `d9eea30`)
**Date:** 2026-10-12
**Policy:** Correctness and trust before new features. No new rules, no new features.

## Baseline record

| Item | Value |
|---|---|
| Audited baseline | `d9eea30` — "Independent competitive validation mission (10 phases)" |
| `master` SHA | `35d5858c5c41eaff42b734326d978572f8545d1d` (587-rule release; **no `main` ref exists** — discrepancy recorded) |
| Working tree at branch creation | Clean except pre-existing `aegis` binary build artifact (untouched, uncommitted) |
| Remediation branch | `fix/post-audit-reliability` |

## Severity resolution policy (for duplicate consolidation)

1. Higher severity wins by default.
2. Lower severity wins only when demonstrably correct:
   - The check is a hardening/detective/recovery recommendation, not a vulnerability
     (consistent with how similar controls are rated elsewhere in the registry).
   - The higher severity is inconsistent with the control class.
3. Each decision is documented per pair below.

## Consolidation mechanism

For exact duplicates: the older (lower-ID) rule is canonical. The newer duplicate is
**removed from its pack's `Rules()` registration and its code deleted**. A
`docs/audit/DEPRECATED_RULE_IDS.md` mapping (removed ID → canonical ID) is published
for suppression/baseline migration. Rationale: keeping dead rules registered to
preserve a count would perpetuate the "inflated rule count" finding the audit flagged.

For partial overlaps: the better logic is ported to the canonical (older) rule;
the duplicate is removed.

## Defect 1: Duplicate rule pairs (46 pairs, 77 distinct rules)

### Classification summary

| Class | Count | Action |
|---|---|---|
| Exact semantic duplicate | 38 | Consolidate to older ID |
| Partial overlap (one strictly better) | 5 | Port better logic to older ID, remove newer |
| Intentionally distinct | 2 | Keep both |
| False duplicate (title collision) | 1 | Keep both, fix misleading title |
| Dead rule (typo'd resource type, never fires) | 2 | Fix type → becomes exact dup → consolidate |

### Per-pair classification

| # | Pair | Class | Canonical | Removed | Severity decision |
|---|---|---|---|---|---|
| 1 | AWS-316 / AWS-621 | Exact dup | 316 | 621 | medium (higher wins) |
| 2 | AWS-320 / AWS-550 | Exact dup | 320 | 550 | high (higher wins) |
| 3 | AWS-321 / AWS-549 | Exact dup | 321 | 549 | high (higher wins) |
| 4 | AWS-321 / AWS-715 | Exact dup | 321 | 715 | high (higher wins) |
| 5 | AWS-549 / AWS-715 | Exact dup | — | both (dups of 321) | — |
| 6 | AWS-327 / AWS-332 | Intentionally distinct | both kept | — | — (v1 vs v2 API GW) |
| 7 | AWS-327 / AWS-830 | Dead rule | 332 | 830 | medium |
| 8 | AWS-332 / AWS-830 | Exact dup (after type fix) | 332 | 830 | medium |
| 9 | AWS-404 / AWS-831 | Dead rule | 404 | 831 | high |
| 10 | AWS-420 / AWS-782 | Exact dup | 420 | 782 | high |
| 11 | AWS-430 / AWS-815 | Exact dup | 430 | 815 | **medium** (lower correct: operational control) |
| 12 | AWS-440 / AWS-719 | Exact dup | 440 | 719 | **medium** (lower correct: operational control) |
| 13 | AWS-605 / AWS-701 | Exact dup | 605 | 701 | low |
| 14 | AWS-608 / AWS-718 | Exact dup | 608 | 718 | low |
| 15 | AWS-625 / AWS-752 | Exact dup | 625 | 752 | **low** (lower correct: detective control) |
| 16 | AZR-005 / AZURE-036 | Exact dup | AZR-005 | 036 | high (higher wins) |
| 17 | AZURE-012 / AZURE-213 | Partial (012 broader) | 012 | 213 | high |
| 18 | AZURE-020 / AZURE-312 | Exact dup | 020 | 312 | high (higher wins) |
| 19 | AZURE-025 / AZURE-206 | Exact dup | 025 | 206 | high |
| 20 | AZURE-028 / AZURE-146 | Exact dup | 028 | 146 | medium (higher wins) |
| 21 | AZURE-028 / AZURE-203 | Exact dup | 028 | 203 | medium |
| 22 | AZURE-146 / AZURE-203 | Exact dup | — | both (dups of 028) | — |
| 23 | AZURE-029 / AZURE-126 | Exact dup | 029 | 126 | medium |
| 24 | AZURE-029 / AZURE-193 | Exact dup | 029 | 193 | medium |
| 25 | AZURE-126 / AZURE-193 | Exact dup | — | both (dups of 029) | — |
| 26 | AZURE-030 / AZURE-198 | Exact dup | 030 | 198 | **low** (lower correct: recovery aid) |
| 27 | AZURE-031 / AZURE-123 | Exact dup | 031 | 123 | medium |
| 28 | AZURE-032 / AZURE-144 | Exact dup | 032 | 144 | medium (higher wins) |
| 29 | AZURE-032 / AZURE-196 | Exact dup | 032 | 196 | medium |
| 30 | AZURE-144 / AZURE-196 | Exact dup | — | both (dups of 032) | — |
| 31 | AZURE-034 / AZURE-120 | Exact dup | 034 | 120 | **low** (lower correct: detective control) |
| 32 | AZURE-038 / AZURE-188 | Exact dup | 038 | 188 | medium |
| 33 | AZURE-040 / AZURE-190 | Partial (190 handles empty) | 040 | 190 | medium (port 190's logic) |
| 34 | AZURE-042 / AZURE-202 | Partial (042 strictly better) | 042 | 202 | low (keep 042's logic) |
| 35 | AZURE-057 / AZURE-243 | Partial (243 checks enable) | 057 | 243 | low (port 243's logic) |
| 36 | AZURE-061 / AZURE-109 | Exact dup | 061 | 109 | high (higher wins) |
| 37 | AZURE-062 / AZURE-178 | False duplicate | both kept | — | fix 178's title |
| 38 | AZURE-066 / AZURE-117 | Exact dup | 066 | 117 | low |
| 39 | AZURE-088 / AZURE-251 | Intentionally distinct | both kept | — | — (different schema versions) |
| 40 | AZURE-136 / AZURE-234 | Exact dup | 136 | 234 | low |
| 41 | AZURE-155 / AZURE-298 | Exact dup | 155 | 298 | high (higher wins) |
| 42 | GCP-005 / GCP-121 | Partial (121 handles absent) | 005 | 121 | high (port 121's logic) |
| 43 | GCP-009 / GCP-110 | Exact dup | 009 | 110 | high |
| 44 | GCP-011 / GCP-112 | Partial (112 fixes 011's FN) | 011 | 112 | high (port 112's logic) |
| 45 | GCP-057 / GCP-118 | Exact dup | 057 | 118 | medium |
| 46 | GCP-058 / GCP-119 | Exact dup | 058 | 119 | medium |

**Result:** 40 rules removed, 5 rules gain improved logic, 4 rules kept as intentionally distinct/false-duplicate.

## Defect 2: P4-DEF-01 — AZURE-187 FP on ARM/Bicep Key Vault (HIGH)

- **Reproduction:** ARM template with Key Vault `networkAcls: { defaultAction: "Deny" }` → rule fires with evidence `default_action = ""`.
- **Root cause:** ARM adapter snake_cases top-level property keys but preserves nested map key casing in `evalCtx.eval` (`map[string]any` case: `out[k] = c.eval(e)`). Rule looks up `default_action`, nested key is `defaultAction` → miss → FP.
- **Systemic:** affects any rule reading nested ARM properties.
- **Fix:** recursive snake_case normalization of nested map keys in `eval`.
- **Tests:** ARM + Bicep fixtures, vuln (Allow) + secure (Deny) per format.

## Defect 3: P4-DEF-02 — for_each unresolvable drops whole file (HIGH)

- **Reproduction:** Terraform resource with `for_each` over unresolvable expression → file marked "skipped", `files_parsed: 0`, resources dropped. Warning message claims "analyzed as a single instance" (false).
- **Root cause:** `cmd/aegis/main.go` scan loop: ANY warning diagnostic → file status "skipped" → `continue` drops resources.
- **Fix:** only explicit exclude/no-adapter conditions mark a file skipped; warnings keep the file parsed with resources analyzed. Fix the misleading message.
- **Tests:** unresolvable for_each → file parsed, resource analyzed as single instance, warning present; mixed valid/invalid; malformed input.

## Defect 4: Bicep parser panic (MEDIUM)

- **Reproduction:** `resource A0'''0` → `slice bounds out of range [:18] with length 15` at `bicep.go:201` (`parseKeyword`).
- **Root cause:** `parseStringVal` treats `'''` as multiline opener; on unterminated input, `p.pos += 3` skips past EOF.
- **Fix:** bounds-check before slicing; return controlled diagnostic.
- **Note:** production impact contained (safeParse recovers), but any unwrapped caller crashes.

## Defect 5: Near-quadratic scaling (MEDIUM)

- **Status:** investigate separately. Profile below/around/above 4k resources, identify hot path, document. Targeted fix or justified deferral acceptable.
