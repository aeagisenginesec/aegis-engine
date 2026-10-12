# Phase 7 — Remediation Safety Report

**Scope:** `aegis fix` (dry-run default, `--apply`, `--force`, `--rule`) — patch validity, minimality,
apply safety, safety classifications, IAM/networking refusal, secret handling, and target scope.
**Verdict: PASS with findings.** No file corruption and no secret leakage were observed in 20 cases.
Two real defects were found (both completeness/correctness, neither unsafe): a JSON-output corruption
and a silent no-op when multiple files declare the same resource address. Details in §9.

| Item | Value |
|---|---|
| Engine | `~/workspace/aegis-engine`, branch `fix/demo-defects-d1-d3`, HEAD `0c28621` |
| Binary under test | built from that HEAD: `export PATH=~/workspace/toolchain/go/bin:$PATH && go build -o /tmp/aegis-p7 ./cmd/aegis/` |
| Docs reviewed | `docs/REMEDIATION_SAFETY.md`; `internal/remediation/{remediation,fixers,safety}.go`; `runFix` in `cmd/aegis/main.go` |
| Corpus | `tests/demos/aws-security-demo/vulnerable/` (34 files), `secure/` (spot checks), `benchmark/corpus-v2/` fixtures referenced; custom fixtures for secret/symlink cases |
| Cases | 20 (single-file 01–15, 17; multi-file 16, 18, 19; bulk 20) |
| Findings exercised | 200 in bulk (case 20) + 23 fixable-rule findings across 8 rules in single-file cases; rules covered include 001, 002, 003, 004, 006, 007, 008, 009, 010, 011, 012, 101, 338, 501–504, 604, 666/667/673 (≥10 rules ✓, ≥25 findings ✓) |
| Classifications covered | SAFE (001, 007, 008, 009, 010, 012), CONDITIONAL (002, 011), MANUAL (003, 338 — no fixer by design) |
| Raw evidence | `docs/audit/raw/phase7/cases/<n>/` — `before.tf`/`after.tf` (or `before/`/`after/` for multi-file), `fix_output.json`, `dryrun.json`, `rescan.json`, `diff.txt` |
| Constraints honored | Engine source untouched (read-only); fixtures only copied; scratch in `/tmp` then relocated to `~/workspace/.p7-work/` (outside the repo) after `/tmp` (512M tmpfs) filled up with sibling phases' artifacts — other agents' files were not touched; nothing committed; branch unchanged |

## 1. Per-case results

`valid?` = dry-run patch syntactically valid, minimal, and addresses the finding.
`applied` = patches with `"applied": true` in the `--apply` JSON.
`rescan` = fixable-rule findings remaining after apply (all converge on a second run unless noted).
`new` = new findings introduced by the patch. `idem` = repeat run proposes nothing once fixpoint reached.

| # | Fixture | Rule / class | Dry-run patches (valid?) | Applied (run 1) | Rescan left | New | Idem? | Unrelated untouched? |
|---|---|---|---|---|---|---|---|---|
| 01 | 03-s3-no-encryption | 001 SAFE, 012 SAFE | 001 ✓, 012 ✓ | 001 only — 012 skipped (same-line overlap, §9 F3) | 012 → fixed on run 2 | 0 | yes (2 runs) | yes |
| 02 | 05-s3-no-versioning | 001 SAFE, 012 SAFE | 001 ✓, 012 ✓ | 001 only | 012 → run 2 | 0 | yes | yes |
| 03 | 01-s3-public-acl | 002 COND, 001 SAFE, 012 SAFE | all 3 ✓ | 001 + 002 (different lines) | 012 → run 2 | 0 | yes | yes (one cosmetic note §9 F5) |
| 04 | 11-rds-unencrypted | 007 SAFE, 008 SAFE | both ✓ | 007 only (same-line overlap) | 008 → run 2 | 0 | yes | yes |
| 05 | 13-rds-no-deletion-protection | 007 SAFE, 008 SAFE | both ✓ | 007 only | 008 → run 2 | 0 | yes | yes |
| 06 | 12-rds-public | 011 COND, 007 SAFE, 008 SAFE | all 3 ✓ | 007 + 011 (different lines) | 008 → run 2 | 0 | yes | yes |
| 07 | 15-ebs-unencrypted | 009 SAFE | 009 ✓ | 009 | none | 0 | yes (1 run) | yes |
| 08 | 16-cloudtrail-no-validation | 010 SAFE | 010 ✓ | 010 | none | 0 | yes (1 run) | yes |
| 09 | 02-s3-public-policy | 001/012 SAFE + **003 MANUAL** | 001 ✓, 012 ✓; **003: nothing proposed** | 001 | 012 → run 2; 003 correctly untouched | 0 | yes | yes |
| 10 | 26-ssm-plaintext | **338 MANUAL (secret)** | **nothing proposed** | n/a | n/a | 0 | yes | yes (file byte-identical) |
| 11 | 06-sg-open-ssh | networking (004/604) | **nothing proposed** | n/a | n/a | 0 | yes | yes |
| 12 | 07-sg-open-egress | networking | **nothing proposed** | n/a | n/a | 0 | yes | yes |
| 13 | 08-iam-admin-wildcard | IAM (006, 501–504) | **nothing proposed** | n/a | n/a | 0 | yes | yes |
| 14 | 09-iam-open-trust | IAM (101, 666/667/673) | **nothing proposed** | n/a | n/a | 0 | yes | yes |
| 15 | 10-iam-admin-managed | IAM | **nothing proposed** | n/a | n/a | 0 | yes | yes |
| 16 | sg.tf + iam.tf + trust.tf | IAM/networking, `--force` | nothing proposed with or without `--force`; WARNING on stderr with `--force`; files byte-identical | n/a | n/a | 0 | yes | yes |
| 17 | custom RDS + fake secret | 007/008 SAFE, 339 MANUAL | both ✓; secret absent from all outputs | 007 (run 1), 008 (run 2) | none after run 2 | 0 | yes (run 3: 0 patches) | yes; secret line byte-identical |
| 18 | real.tf + symlink→outside | 009 SAFE | 009 ✓ (symlink target not discovered) | 009 | none | 0 | yes | yes; outside file untouched, symlink preserved |
| 19 | fixed.tf + vuln.tf | 009 SAFE | 009 ✓ only | 009 | none | 0 | yes | **fixed.tf byte-identical** |
| 20 | all 34 vulnerable files | 001,002,007,008,009,010,011,012 | 15 proposed run 1 | 3 (002, 009, 010) — 12 never apply, §9 F2 | 001,007,008,011,012 remain | **0** | **no — proposes 12 forever** | yes |

Error-level diagnostics: **0 in every rescan** (all 20 cases). Backup files (`.bak`, `*~`): **none written in any case** —
`applyEdits` writes patched content directly with no backup copies.

## 2. Dry-run analysis (task step 1)

- **Syntactic validity:** every proposed patch is a minimal unified diff; applied results re-parse with zero
  error diagnostics in all cases (validated both by the engine's own `ValidatePatch` gates —
  `ResourceMissing` and error-diagnostic checks — and by independent re-scans).
- **Minimality:** `boolFixer` replaces/inserts exactly one attribute line; `blockFixer` inserts exactly one
  nested block before the resource's closing brace; nothing is reformatted and no adjacent lines are touched.
  One cosmetic exception: fixer002 rewrites `  acl    = "public-read"` as `  acl = "private"`,
  normalizing the column alignment (single line changed; content-correct, not byte-minimal) — §9 F5.
- **Addresses the finding:** each patch's `fixed: true, new_findings: 0` in validation, confirmed by
  independent re-scan (finding gone, nothing new).
- **Dry-run writes nothing:** sha256 of the target file identical before/after `fix` without `--apply` (case 17).
- `--rule=RULEID` filter spot-checked: only the requested rule's patches proposed.

## 3. Apply verification (task step 2)

For every applied case: (a) file re-parses (0 error diagnostics); (b) the targeted finding is gone on re-scan;
(c) **zero new findings** in all 20 cases; (d) `diff` shows every changed line relates to the finding
(e.g. case 06: `publicly_accessible = true→false` line flip + one `storage_encrypted = true` insert —
nothing else); (e) idempotence holds once fixpoint is reached — with two caveats: multi-patch resources
need 2 runs to converge (§9 F3), and the bulk duplicate-address case never converges (§9 F2).

## 4. Safety classification verification (task step 3)

- **SAFE** (001, 007, 008, 009, 010, 012): auto-applied exactly as documented; additive-only or safe boolean enables.
- **CONDITIONAL** (002, 011): fixer behaves identically to SAFE mechanically (proposed + applied without extra
  prompting). The classification is documentary — operators are expected to review the shown diff before
  `--apply`, since flipping a public ACL or DB reachability can break intentional setups. No technical
  enforcement distinguishes CONDITIONAL from SAFE today.
- **MANUAL** (003 bucket policy, 338 SSM plaintext, and by code comment 004/005/006, 101–104): **no fixer
  exists; nothing is ever proposed** (cases 09, 10). Correct.
- **IAM/networking refusal:** cases 11–15 and 16 without `--force` → `{"applied": false, "patches": []}`,
  exit 0, files byte-identical. **With `--force`:** stderr WARNING
  (`--force enables patches on IAM/networking resources. Review every diff before applying.`), but still
  `patches: []` — no shipped fixer addresses a blocked type, so `--force` currently changes nothing;
  `AllowBlocked` is purely a backstop for future fixers. With `--force --apply` the top-level
  `"applied": true` is emitted even with zero patches (it means "--apply mode was on", §9 F4). Files unchanged.

## 5. Secret-handling verdict (task step 4) — PASS

Custom fixture with `password = "P7FAKESECRET-s3cr3t-v4lue-9z8x7w6v"` adjacent to fixable attributes:
the secret appears in **none** of — dry-run text stdout, dry-run JSON, `--apply` JSON, `--apply` stderr,
or patch diffs (diffs only render edited lines; the secret's line is never edited). No `.bak`/backup files
exist anywhere after apply. `after.tf` preserves the secret line byte-identical (fixer must not mangle what
it doesn't own — confirmed). The 339 plaintext-password finding itself is MANUAL: no patch proposed.
(`aegis scan` JSON also does not echo the value.)

## 6. Scope / symlink verdict (task step 5) — PASS

Case 18: target dir held `real.tf` (fixable) plus `link.tf → /tmp/.../outside/victim.tf` (fixable, outside target).
Results: the scanner's discovery **does not follow the symlink** (only `real.tf` findings reported);
`fix --apply` patched only `real.tf`; the outside file is **byte-identical** (sha256 match before/after);
`link.tf` remains a symlink (not replaced). Defense in depth confirmed in code and empirically:
`copyTree` skips symlinks during validation, and `ValidatePatch` rejects any patch whose file resolves
outside the target dir.

## 7. Bulk behavior (case 20)

All 34 vulnerable fixtures (200 findings, ~100 rules) in one target: run 1 proposed 15 patches, applied 3
(002, 009, 010 — the only fixable findings on **unique** resource addresses); findings 200 → 197; **zero new
findings**; 0 error diagnostics. Runs 2–5 each proposed the same 12 patches and applied **0** — see §9 F2.

## 8. What was NOT found (positive results)

No fixer corrupted a file in 20 cases; no patch introduced a new finding; no IAM/networking resource was
modified with or without `--force`; no secret was echoed into any log, diff, or JSON; no file outside the
target directory was touched; no backup/secret-bearing side files were created; dry-run never writes.

## 9. Findings (defects, with severity)

### F1 [LOW] `fix --format=json --apply` emits non-JSON trailing output
`runFix` prints `\nre-scan: findings N → M` to **stdout** even in `--format=json` mode
(`cmd/aegis/main.go`, after the JSON document). Every `fix_output.json` in `raw/phase7/cases/` ends with this
line, which breaks strict JSON parsers (this harness had to split on it). Fix: print the re-scan summary to
stderr in JSON mode, or include it as a JSON field.

### F2 [MEDIUM-LOW] Duplicate resource addresses across files: silent permanent no-op (+ wrong-file attribution)
When ≥2 files in the target declare the same resource address (invalid Terraform per module, but the scanner
still reports per-file findings), two compounding defects appear:
1. `ValidatePatch`'s "fixed" check keys on `(rule_id, resource-address)` **without the file**, so a patch that
   fixes file A never validates while file B fires the same rule on the same address → `--apply` **silently
   applies nothing, forever**. Case 20: runs 2–5 propose the identical 12 patches, apply 0, exit 1 each time —
   automation looping `fix --apply` until exit 0 would **spin forever** with no explanatory message.
2. `ProposeAll`'s `byAddr` keeps only the **first** resource per address, so fixers read attributes/spans from
   the wrong file: all 001/012 block-insert patches for findings in files 02–05 were computed against **file 01's**
   closing brace (`cases/20/apply_run1.json` diff headers), and the **011 patch was never proposed at all**
   in bulk (the first `aws_db_instance.demo` lacks `publicly_accessible`, so `boolFixer` declined) — yet the
   identical fixture fixes cleanly solo (case 06). Behavior is directory-neighbor-dependent.
No unsafe write resulted (the conservative gates held — that is why it no-ops rather than corrupts), but the
silent non-convergence and cross-file misattribution are real. Suggested: key finding identity by
(rule, resource, file), match findings to their own file's resource, and warn when an address collides.

### F3 [INFO] Same-line overlap: one patch per `--apply` run
Two inserts targeting the same closing-brace line (001+012, 007+008) — the first by rule-ID order applies,
the rest are skipped as "overlaps … patch". Safe and conservative, converges on re-run (verified), but a
single `--apply` is not "apply all". Consider merging adjacent inserts or documenting the fixpoint behavior.

### F4 [INFO] `"applied": true` with zero patches is misleading
`--force --apply` on IAM-only input returns `{"applied": true, "patches": []}` — the flag reports mode, not
effect. Minor semantic wart (case 16: `force_apply.json`).

### F5 [INFO] fixer002 normalizes attribute alignment
`  acl    = "public-read"` → `  acl = "private"`: one line changed, but column alignment with neighboring
attributes is not preserved. Cosmetic only.

## 10. Raw data index

`docs/audit/raw/phase7/cases/<n>/`:
- `01`–`15`, `17`: `before.tf`, `after.tf`, `fix_output.json` (raw `--apply` JSON incl. the F1 trailing line),
  `dryrun.json`, `rescan.json`, `diff.txt`, `run.log` (exit codes)
- `16` (IAM/networking): `before/` + `after/` (3 files, identical), `fix_output.json` (no `--force`),
  `force.json` + `force_apply.json` (+ stderr files showing the WARNING)
- `17` (secret): as above; secret value `P7FAKESECRET-s3cr3t-v4lue-9z8x7w6v` appears only in `before.tf`/`after.tf`
- `18` (symlink): `before/real.tf`, `after/real.tf`, `victim_outside_before.tf`, sha256 before/after of the
  outside file, `fix_output.json`, `scope_notes.txt`
- `19` (mixed): `before/{fixed,vuln}.tf`, `after/{fixed,vuln}.tf`, `fix_output.json`
- `20` (bulk): `scan_before.json`, `apply_run1..5.json`, `rescan.json`
