# 14 — Real CI/CD Integration Validation (Item 4)

**Mission:** Top-tier validation, item 4 of 6 parallel workers
**Date:** 2026-10-13
**Branch:** `mission/top-tier-validation` (no checkout / commit / merge / stash
performed by this worker; no GitHub repo created, nothing pushed)
**Binary under test:** `go build` of branch HEAD → `/tmp/aegis-item4/aegis`
(`aegis 1.0.0`, `doctor`: **1,151 rules loaded**, all self-checks pass)
**Prior work reused, not redone:** `docs/audit/08_CI_INTEGRATION_REPORT.md`
(Phase 9). Where this report agrees with Phase 9 it says so and cites it;
where it goes further (coverage cross-check, SARIF chunking, PR comments,
GitLab MR notes, baseline-refresh automation) that is new.

## 1. What was delivered

| File | What it is |
|---|---|
| `.github/workflows/aegis.yml` | **New.** PR security gate: 4 jobs (`scan`, `upload-sarif`, `pr-comment`, `baseline-refresh`). Builds from source, scans JSON + SARIF, audits completeness, splits SARIF into ≤5,000-result chunks, uploads each chunk under its own code-scanning category, upserts one PR comment, supports baseline + baseline-refresh PRs. |
| `.gitlab-ci.yml` | **New** (repo previously had none). Equivalent: `aegis-scan` (gate + SARIF via `reports:sarif`), manual `aegis-baseline`, optional `aegis-mr-note`. |
| `docs/audit/14_CI_CD_VALIDATION.md` | This report. |

Deliberately **not** touched: `.github/workflows/aegis-scan.yml` (pre-existing
example), `examples/github-actions/aegis.yml`, `docs/CI_INTEGRATION.md`
(both still carry the issues Phase 9 flagged — no `--strict`, GitLab
`reports:sast` pointed at native JSON; see §6), and every other file.
`git status` at end of work shows only these two new workflow files (plus
other workers' files) from this worker.

Both workflows embed the **same** completeness-audit Python (verified
byte-identical after YAML parsing, §4.1) so GitHub and GitLab gates behave
identically.

## 2. How it was tested — the honest label

| Workflow part | Verdict | What ran live | What was simulated / blocked |
|---|---|---|---|
| GH `scan` job: build, doctor, both scans, audit, split, gate decision | **SIMULATED, faithful** | The **literal** gate-step `run:` text extracted from parsed YAML, executed with `bash -e` (the runner's errexit default), with only `GITHUB_OUTPUT` / `GITHUB_STEP_SUMMARY` stubbed. Build step replaced by the prebuilt HEAD binary (same binary, built from source + `doctor` green). | No `act` (not installed) and no Docker daemon in the sandbox, so no hosted runner. `actions/checkout` / `setup-go` replaced by local files / local go1.25.4. |
| GH `upload-sarif` (per-chunk matrix) | **BLOCKED-ON-REPO-CREATION** | Nothing (needs GitHub API). Chunk files + manifest validated locally (§4.4). | `codeql-action/upload-sarif`, matrix expansion, category handling. |
| GH `pr-comment` (github-script upsert) | **BLOCKED-ON-REPO-CREATION** | JS syntax-checked with `node --check` (PASS); `bash -n` N/A. | `github-script` action, comment API, marker upsert. |
| GH `baseline-refresh` (dispatch → PR via `gh`) | **BLOCKED-ON-REPO-CREATION** | `bash -n` PASS on every step; the scan/`--baseline-out` command itself verified live (§4.5). | `git push` + `gh pr create` (needs a repo + token). |
| GitLab `aegis-scan` | **SIMULATED, faithful** | The **literal** `script:` lines (anchors expanded by the YAML parser) executed with `bash -e`, `go build` line stripped (fixture dirs are not Go repos; build covered separately). | No GitLab runner; `golang:1.25` image → local go1.25.4; `apt-get install python3` step skipped (python3 present locally). |
| GitLab `aegis-baseline` | **SIMULATED, faithful** | Literal script (minus `go build`) on a fixture: exit 0, `.aegis/baseline.json` written with 6 fingerprints. | No runner (same as above). |
| GitLab `aegis-mr-note` | **BLOCKED-ON-REPO-CREATION** | Guard path verified live: no `audit.json` → clean exit 0, no API call. `bash -n` PASS. | `curl` POST to the GitLab MR-notes API (needs a project + `AEGIS_MR_NOTE_TOKEN`). |
| SARIF validation | **LIVE (structural)** | Phase 9 validator (`docs/audit/raw/phase9/validate_sarif.py`): version, `ruleId`→`rules[]` coverage, ≥1 location, ≤5,000 results, <10 MB. | Official SARIF 2.1.0 JSON-schema check **skipped**: no schema file is cached locally and this task forbids external calls, so the schema could not be downloaded. Phase 9 already schema-validated the same emitter output. |

## 3. Scanner behaviour the workflows are built around

All verified live against the HEAD binary in this session (not inherited):

| # | Behaviour | Evidence | Workflow consequence |
|---|---|---|---|
| 1 | Exit codes 0 / 1 / 2 match the documented contract | Clean dir → 0; violating file → 1 (`--fail-on=high`); `--strict` + broken file → 2; nonexistent target → 2; unknown `--fail-on` → 2 | Gate keys off the JSON scan's exit code |
| 2 | `*.tfvars` has **no adapter**: reported as `failed`, reason `parse or read failure`, even though the diagnostic says "skipped" | `vars.tfvars` alone + `--strict` → exit 2 | Scans use `--exclude="*.tfvars"`; excluded tfvars appear as `skipped`, audit lists them |
| 3 | `*.tf.json` (Terraform JSON syntax) is treated as a generic manifest and **SKIPPED without analysis — even under `--strict`** | `good.tf.json` → status `skipped`, exit 0 | Audit flags `tfjson_skipped` with an explicit "convert to `.tf`" warning; never assume .tf.json is covered |
| 4 | Files over `--max-file-size` (default 10 MiB) are **silently absent** from completeness under default flags: `files_discovered: 0`, no diagnostic, exit 0 | 11.5 MB `.tf` scanned with defaults → discovered 0, exit 0 (confirmed twice) | Coverage cross-check: every on-disk IaC file must appear in completeness; missing file → audit exit 3, gate fails |
| 5 | `--max-file-size` flag does **not** raise the enforced cap: `--max-file-size=20000000` still fails the 11.5 MB file with "file exceeds 10 MiB limit" (though it does change discovery: the file then appears as `failed` instead of vanishing) | Same file + flag → discovered 1, failed, reason cites 10 MiB | Workflows do not rely on the flag; the cross-check catches both the silent-drop and the failed-file case |
| 6 | SARIF carries **no completeness/diagnostic data** (`runs[]` = `tool` + `results` only) | SARIF of the mixed fixture: run keys `['tool', 'results']`, no `properties`/`invocations` | The JSON artifact is the completeness evidence; both formats are uploaded as artifacts |
| 7 | `--color` **does not exist**: `flag provided but not defined: -color`, exit 2 | Direct invocation | Workflows never pass `--color` (the task brief mentioned it; the binary rejects it) |
| 8 | `for_each` with an unresolvable expression is analysed as a single instance, with a **warning** diagnostic ("instance count unknown, findings may be incomplete") | `foreach.tf` parsed; warning diagnostic present | Reported in the audit's skipped/diagnostic surface; not a gate failure by itself |
| 9 | `.tf.json` / `.yaml` / `.yml` / `.json` / `Dockerfile*` / `.bicep` are all discovered (as their adapter or as `manifests`); `README.md`, `go.mod` are ignored; `.git/` and `node_modules/` are silently excluded from discovery | Discovery probe dir (5 discovered: `.github/workflows/ci.yml`, `.pre-commit-hooks.yaml`, `cfn.yaml`, `main.tf`, `package.json`); `vendor/` IS scanned; `.git/` + `node_modules/` are not | Audit enumeration mirrors exactly this set (incl. `.git`/`node_modules` exclusions) |
| 10 | Baselines work per spec: capture → suppress → only-new surfaces; fingerprints stable across runs on the same tree | v1 capture (6 fingerprints) → add `v2.tf` → rescan with baseline: **6 findings, all on v2**; re-capture on the v1-only tree → byte-identical fingerprint sets | Gate auto-applies `.aegis/baseline.json` when present; refresh via dispatch PR (GH) / manual job (GL) |
| 11 | The redirect-created output file is itself scanned: `> aegis.json` creates an empty `aegis.json` before the walk, so it appears in completeness as `parsed manifests` | Clean fixture: `discovered=2` (`empty.tf` + `aegis.json`) | Cosmetic only; the audit excludes the workflow's own outputs from the missing-file check |

## 4. Local test results

Simulation harness: `/tmp/aegis-item4/simulate.py` (scratch only — it executes
the literal workflow code extracted from the parsed YAML; fixture repos under
`/tmp/aegis-item4/sim/`).

### 4.1 Workflow-file checks — all PASS

- YAML parses for both files (PyYAML; the GH `on:` key reads as boolean
  `True` under YAML 1.1 — normal for GitHub workflows, which use GitHub's own
  parser).
- Embedded audit Python **byte-identical** between the two workflows after
  YAML dedent; audit + split scripts compile (`py_compile`).
- `bash -n` PASS on every GH `run:` block and every GitLab job script
  (joined). `node --check` PASS on the PR-comment script.
- `git status` confirms only the two new workflow files (+ this report) from
  this worker.

### 4.2 Scenario matrix — all PASS

Gate exits: **0** clean · **1** findings ≥ threshold · **2** operational error
· **3** incomplete scan (audit-synthesised; Aegis itself has no such code).

| Scenario | Runner | Gate exit | Audit complete | Notes |
|---|---|---|---|---|
| clean (comment-only `.tf`) | GH | 0 ✅ | yes | 0 findings |
| vulnerable (rich file, 35 findings) | GH | 1 ✅ | yes | Gate fails as designed |
| vulnerable | GL | 1 ✅ | yes | Same verdict as GH |
| mixed-partial (good + broken + junk + binary + tfvars) | GH | 2 ✅ | **no** | 3 failed files named (`binary.tf`, `broken.tf`, `junk.tf`); tfvars listed as skipped, not failed |
| huge-only (single 11.5 MB `.tf`) | GH | **3** ✅ | **no** | Scanner exits 0 (silent drop, §3 #4); audit catches it via `missing_files: [huge.tf]` — the key test |
| huge-only | GL | **3** ✅ | **no** | Same catch on GitLab |
| mixed-full (partial + huge + `.tf.json` + `for_each` + K8s YAML) | GH | 2 ✅ | **no** | `tfjson_skipped` flagged; `huge.tf` missing; `for_each` file parsed, not failed |
| tfvars-only (exclusion path) | GH | 0 ✅ | yes | tfvars → skipped via `--exclude`, no strict failure |
| huge-corpus (144 files, **5,042 findings**) | GH | 1 ✅ | yes | Split → 2 chunks (5,000 + 42); chunk total == original total; both chunks validator-PASS (§4.4) |
| baseline (v1 capture → add `v2.tf` → rescan) | GH | 1 ✅ | yes | Only v2's 6 findings surface; v1 suppressed |
| baseline fingerprint stability | direct | — ✅ | — | Re-capture on identical tree → identical fingerprint sets (6 entries) |
| GitLab baseline job (literal script) | GL | 0 ✅ | — | `.aegis/baseline.json` written, 6 fingerprints |
| GitLab MR-note guard (no `audit.json`) | GL | 0 ✅ | — | Clean skip, no API call |

### 4.3 Exit-code matrix (binary, direct invocation) — 6/6 match contract

| Case | Got | Expected |
|---|---|---|
| Empty/comment-only dir | 0 | 0 ✅ |
| Violating file, `--fail-on=high` | 1 | 1 ✅ |
| Violating file, default flags | 1 | 1 ✅ |
| Broken `.tf` + `--strict` | 2 | 2 ✅ |
| Nonexistent target | 2 | 2 ✅ |
| Unknown `--fail-on` / `--color` | 2 | 2 ✅ |

### 4.4 SARIF validation (Phase 9 validator, structural checks)

| Artifact | Results | Verdict |
|---|---|---|
| `vuln` SARIF (single-chunk path) | 35 | **GITHUB-ACCEPTANCE: PASS** (36,468-byte chunk) |
| Huge-corpus chunk 01 | 5,000 | **GITHUB-ACCEPTANCE: PASS** (1,514,895 bytes) |
| Huge-corpus chunk 02 | 42 | **GITHUB-ACCEPTANCE: PASS** (13,386 bytes) |
| Huge-corpus original (unsplit) | 5,042 | Would **FAIL** the ≤5,000 check — this is exactly why the splitter exists |

Schema check skipped in all cases (no cached schema, no external calls —
§2). Absolute-path `artifactLocation.uri`s retained (GitHub accepts them;
relative paths would give cleaner alert links — noted as a scanner-side
improvement, not a workflow defect).

### 4.5 Baseline-refresh mechanics — verified except the API step

- GH `baseline-refresh` scan command (`--baseline-out`, `--strict`,
  `--exclude`) verified live in the baseline scenario (exit 1 with findings,
  baseline written).
- `git commit` / `git push` / `gh pr create` steps are `bash -n`-clean but
  untested live → **BLOCKED-ON-REPO-CREATION**.

## 5. BLOCKED-ON-REPO-CREATION — what needs a real repo, and exactly how to unblock

No GitHub repo exists for Aegis yet. Nothing below can run until one does.
**Do not** attempt any of these steps against a repo that does not exist.

### 5.1 GitHub Actions (`.github/workflows/aegis.yml`)

| # | Blocked step | Unblock (in order, after the repo exists) |
|---|---|---|
| 1 | Push the branch containing `.github/workflows/aegis.yml` | `git push origin mission/top-tier-validation` (or merge it to `main` first — the workflow triggers on `pull_request`, `push` to `main`, and `workflow_dispatch`). |
| 2 | First `scan` job on a real runner | Open any PR (or push to `main`). Check: job builds with `setup-go` 1.25, `aegis doctor` passes, gate exit matches the local matrix (§4.2). |
| 3 | `upload-sarif` matrix job | After step 2, open the repo → **Security → Code scanning alerts**. Expect alerts under categories `aegis-chunk-01`, `aegis-chunk-02`, … (one per chunk). If a scan yields ≤5,000 findings there will be exactly one chunk. Verify the alert count equals the JSON finding count (chunking must not drop results). |
| 4 | `pr-comment` | On the same PR, expect exactly one comment titled "Aegis IaC gate — …" (marker `<!-- aegis-scan-summary -->`). Push a second commit: the comment must be **updated in place**, not duplicated. |
| 5 | `baseline-refresh` | Actions → "Aegis IaC Security Gate" → Run workflow → tick `update_baseline` → Run. Expect a PR `chore(aegis): refresh baseline` touching only `.aegis/baseline.json`. Review the diff before merging (every added fingerprint is a finding the gate will stop flagging). Then re-run the gate with the baseline committed: only new findings should fail it. |
| 6 | Fork-PR caveat (known GitHub limitation, unverified live) | `upload-sarif` from a fork PR may fail: the `GITHUB_TOKEN` on `pull_request` from forks cannot write `security-events` in some configurations. If it fails, the gate job itself still fails/passes correctly and the artifacts still upload — only code-scanning ingestion is affected. Do not "fix" this by switching to `pull_request_target` without a security review (that event runs in the base-repo context). |

### 5.2 GitLab CI (`.gitlab-ci.yml`)

| # | Blocked step | Unblock (in order, after the project exists) |
|---|---|---|
| 1 | Import the project + enable a runner | Push the repo to GitLab (self-managed or SaaS) with a shared or project runner that can run the `golang:1.25` image. `.gitlab-ci.yml` is picked up automatically on push. |
| 2 | First `aegis-scan` pipeline | Open an MR (or push to `main`). Check: `apt-get install python3` step succeeds in `golang:1.25`; gate exit matches §4.2; artifacts contain `aegis.json` + `aegis.sarif` + `audit.json` + `aegis-summary.md`. |
| 3 | `reports:sarif` ingestion | On **Ultimate** only: expect the MR security widget / Vulnerability Report to list Aegis findings. On other tiers expect no widget — the file stays downloadable in artifacts and the exit-code gate still works. This tier behaviour is GitLab-documented, not something this config can change. |
| 4 | `aegis-mr-note` | Create a project access token with `api` scope → Settings → CI/CD → Variables → add masked variable `AEGIS_MR_NOTE_TOKEN`. Re-run a pipeline on an MR: expect a summary note on the MR. Known cosmetic limitation: one new note per pipeline run (the API has no upsert). |
| 5 | `aegis-baseline` | Pipelines → run `aegis-baseline` (manual) → download its `.aegis/baseline.json` artifact → **review it** → commit it to the repo. Runners cannot safely commit back on their own, by design. |

### 5.3 Not blocked, but recommended after unblocking

- **SHA-pin the actions** (`actions/checkout`, `setup-go`, `upload-artifact`,
  `download-artifact`, `codeql-action/upload-sarif`, `github-script`).
  Major-version tags are used now because SHAs could not be verified offline.
- **Fix `docs/CI_INTEGRATION.md`** (out of this worker's scope): its GitLab
  example points `reports:sast` at native Aegis JSON (wrong schema — use
  `reports:sarif`), and its GH example lacks `--strict`, `--exclude`, and any
  completeness handling. The tested configs in this item supersede both.
- **Scanner-side issues to file** (all evidenced in §3): `.tfvars` has no
  adapter yet fails the scan; `.tf.json` is silently skipped; >10 MiB files
  vanish from completeness under defaults; `--max-file-size` does not raise
  the enforced cap; SARIF has no completeness block; `--color` is documented
  nowhere the binary honours. The workflows defend against all of these, but
  the fixes belong in the scanner.

## 6. Relationship to Phase 9 (no duplication)

Phase 9 (report 08) already proved: exit codes 8/8, baseline
capture/suppress/expiry/removal, `--strict` failure naming, 500-file
repeatability (byte-identical), and the >5,000-result cap on the self-scan.
This item **reuses** those conclusions and its validator, and adds: the
production workflows themselves; the coverage cross-check that catches the
silent >10 MiB drop Phase 9 did not test; SARIF **chunking** (Phase 9 only
flagged the cap); PR/MR comment jobs; baseline-refresh automation; the
`--max-file-size` flag-ignored finding; the `--color` non-existence finding;
and the `.tf.json`/`.tfvars` failure-mode table. Where Phase 9 simulated the
same steps, this item's simulations execute the literal workflow code rather
than a hand-written equivalent.

## 7. Known limitations of this validation

- No live GitHub/GitLab runner, API, or code-scanning ingestion (§2, §5).
- `act` and Docker are absent from the sandbox, so no runner emulation.
- The self-scan of the full Aegis repo was **not** run as a workflow test:
  a full-repo scan in this sandbox was killed (exit 137, sandbox memory
  pressure with six workers sharing a 512 MB `/tmp`); Phase 9 already
  established the self-scan shape (5,308 findings on the fixture-heavy tree,
  over the 5,000 cap — the splitter exists for exactly this). When the repo
  exists, the first real `scan` job is the self-scan test; expect gate exit 1
  and ≥2 SARIF chunks on this tree unless fixture dirs are excluded.
- The workflows scan `.` with no fixture-dir exclusions: on the Aegis repo
  itself that means intentionally-vulnerable test fixtures fail the gate.
  That is the correct default for a consumer repo; for dogfooding, add
  `--exclude` entries (or a repo-level `aegis.yaml`) as a follow-up decision,
  not silently in this item.
- SARIF chunking preserves result counts but each chunk is a separate
  code-scanning category; alert deduplication across chunks is GitHub's
  behaviour, not tested here.
