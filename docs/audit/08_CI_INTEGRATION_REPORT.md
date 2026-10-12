# 08 — CI Integration Report (Phase 9)

**Mission:** Aegis Independent Competitive Validation and Benchmarking Mission
**Date:** 2026-10-12
**Phase:** 9 of 10 — Real CI Integration
**Branch:** `fix/demo-defects-d1-d3`, HEAD `0c28621`
**Binary under test:** `go build` of HEAD (`/tmp/aegis-p9`; `aegis 1.0.0`)
**Constraint honored:** read-only on Aegis source — no code modified, nothing
committed, no branch switches.

## 1. Live vs simulated — the honest label

| Pipeline | Verdict | What ran live | What was simulated |
|---|---|---|---|
| GitHub Actions (consumer workflow `aegis-demo.yml`) | **SIMULATED** | Every `aegis` invocation (scan, `--baseline-out`, `--strict`, exit codes); SARIF schema validation via `jsonschema` | `act`/runner, `actions/checkout` (file copy instead of `git clone`), release-binary download (staged the audited build), `codeql-action/upload-sarif` (no GitHub API in sandbox) |
| GitHub Actions (shipped example `aegis-selfscan.yml`) | **SIMULATED** | `git clone` (real), `go build` (real), `aegis scan` (real), SARIF validation (real) | `actions/setup-go` (local go1.25.4), `upload-sarif` (no GitHub API) |
| GitLab CI (`.gitlab-ci.yml`) | **SIMULATED** | YAML parse check; every `script:` line executed verbatim in order | No live GitLab runner; `golang:1.25` image → local go1.25.4; artifact upload (file existence check only) |

**Why no live run:** neither `docker` nor `act` existed in the sandbox. `act`
v0.2.89 was installed (small binary, per the brief), but `act` executes every
job step inside containers — with no Docker daemon (`/var/run/docker.sock`
absent, no `docker` binary) a probe workflow hung indefinitely on the missing
socket and had to be killed. Installing a full Docker daemon in this sandbox
was out of scope per the brief. The simulations below execute the workflow
steps **in order, with the real commands**, in clean directories; each delta
vs a real runner is named explicitly in the runner scripts
(`docs/audit/raw/phase9/simulate_github.sh`, `simulate_gitlab.sh`).

## 2. GitHub Actions

### 2.1 Workflow files used (saved under `docs/audit/raw/phase9/`)

- **`aegis-demo.yml`** — consumer pattern (the primary tested workflow): checkout
  → install aegis (release binary) → `aegis scan . --format=sarif --fail-on=high`
  (with `set -o pipefail` + `tee` so the SARIF artifact is kept *and* the aegis
  exit code gates the job) → local SARIF validation → `upload-sarif` (`if:
  always()`). Valid YAML; 5 steps; `contents: read` + `security-events: write`.
- **`aegis-selfscan.yml`** — byte-identical copy of the shipped
  `examples/github-actions/aegis.yml` (dogfood self-scan: `go build` from source).

### 2.2 Simulated run — consumer workflow

Ran `simulate_github.sh` against a scratch copy of
`tests/demos/aws-security-demo/` (85 files):

| Step | Result |
|---|---|
| Checkout (copy) | 85 files staged |
| Install aegis (staged `/tmp/aegis-p9`) | `aegis 1.0.0` |
| `aegis scan . --format=sarif --fail-on=high` | **exit 1** (findings ≥ high — correct gate behavior; log: `logs/gh_consumer_run.log`) |
| Validate SARIF (official 2.1.0 schema + GitHub structural rules) | **PASS** — 421 results, 354,577 bytes |
| `upload-sarif` | SKIPPED (no live GitHub API); step 4 is the checkable part of what GitHub verifies server-side |

### 2.3 Simulated run — shipped example (self-scan of the engine repo)

Real `git clone` of HEAD → real `go build` → real scan of the full repo tree:

- Build: OK (go1.25.4; note: the sandbox needed `GOTMPDIR` redirected — `/tmp`
  is a 512 MB tmpfs shared with other phases' scratch; a real `ubuntu-latest`
  runner has ample disk, so this is a sandbox-only quirk).
- Scan: **exit 1** in ~2 s, SARIF 3.7 MB, stderr empty.
- SARIF validation: **schema PASS, GitHub-acceptance FAIL — 5,308 results
  exceeds GitHub's 5,000-result-per-upload cap** (results over the cap are
  ignored by GitHub; uploads > 25,000 are rejected). The self-scan tree
  contains hundreds of intentionally vulnerable test fixtures, so the shipped
  example as-is would lose ~308 findings on upload. **Recommendation:** scope
  the dogfood scan (e.g. `--exclude` test/benchmark fixture dirs) or document
  the cap in `docs/CI_INTEGRATION.md`.

## 3. SARIF validity verdict

Validated with `validate_sarif.py` (raw/phase9) against the official SARIF
2.1.0 JSON schema (SchemaStore mirror of the OASIS spec, 112 KB, downloaded
2026-10-12) using `jsonschema`, plus GitHub code-scanning structural rules:

| Check | Consumer SARIF (421 results) | Self-scan SARIF (5,308 results) |
|---|---|---|
| Official SARIF 2.1.0 schema | ✅ PASS | ✅ PASS |
| `version: "2.1.0"`, non-empty `runs` | ✅ | ✅ |
| `tool.driver.name` present (`aegis`) | ✅ | ✅ |
| Every `result.ruleId` has a `tool.driver.rules[]` entry | ✅ (all covered) | ✅ |
| Every result has ≥1 location with `artifactLocation.uri` | ✅ | ✅ |
| `level` values in {error, warning, note} | ✅ (65/51/84) | ✅ |
| < 10 MB upload size | ✅ 355 KB | ✅ 3.7 MB |
| ≤ 5,000 results | ✅ | ❌ 5,308 — GitHub would ignore the excess |

**Verdict: GitHub code scanning would accept the consumer-pipeline SARIF.**
The self-scan SARIF is schema-valid but exceeds GitHub's result cap (§2.3).
Minor quality note: `artifactLocation.uri` values are absolute paths
(`file:///home/...` style); GitHub accepts these, but relative repo-rooted
paths produce cleaner alert links.

## 4. Exit-code matrix

All 8 cases match the documented contract (`docs/CI_INTEGRATION.md` + `--help`).
Full log: `raw/phase9/logs/exitcode_matrix.log`.

| Case | Expected | Got |
|---|---|---|
| Empty dir, no findings | 0 | 0 ✅ |
| Findings all below threshold (max=high, `--fail-on=critical`) | 0 | 0 ✅ |
| Vulnerable demo, default flags (any finding fails) | 1 | 1 ✅ |
| Vulnerable demo, `--fail-on=high` | 1 | 1 ✅ |
| Vulnerable demo, `--fail-on=critical` (criticals present) | 1 | 1 ✅ |
| Broken `.tf` + `--strict` | 2 | 2 ✅ |
| Nonexistent target dir | 2 | 2 ✅ |
| Unknown `--fail-on` value | 2 | 2 ✅ |

Implementation (verified by reading, not just behavior):
`threshold = severityRank(--fail-on)` (critical=4/high=3/medium=2/low=1,
default 1); exit 1 iff any finding's rank ≥ threshold; `--strict` + incomplete
scan → 2; scan/report errors → 2. During testing, an early "medium-only"
fixture appeared to contradict the threshold — root cause was a test-harness
error (lexicographic `max()` on severity strings), not an aegis bug; corrected
and re-verified.

## 5. Baselines in CI

Pipeline-shaped test on a scratch repo (log: `raw/phase9/logs/baseline_test.log`;
samples: `raw/phase9/samples/baseline_v1.json`, `baseline_v2_expiry.json`):

| Step | Result |
|---|---|
| Run 1: `scan repo --baseline-out=baseline.json` | 11 findings → 11 fingerprints (`rule_id`+`resource`+`attribute`) |
| PR adds `11-rds-unencrypted.tf` (new violation) | — |
| Run 2: `scan repo --baseline=baseline.json` | **18 surfaced, all on the new resource**; 0 from pre-baseline resources; exit 1 ✅ |
| Fingerprint stability: `--baseline-out` twice, identical code | **byte-identical fingerprint sets** (29/29) ✅ |
| v2 baseline, 1 entry expired (`expires: 2020-01-01`) | entry dropped on load; that 1 finding **resurfaces** (19 surfaced) ✅ |
| v2 baseline, all entries future-expiry | 18 surfaced (new only) ✅ |
| Baseline removed | all 29 findings surface ✅ |

Baselines behave exactly as `docs/BASELINES.md` specifies. CI usage
(`--baseline-out` once, commit `baseline.json`, `--baseline` in the pipeline)
is sound; expiry gives time-boxed exceptions without pipeline changes.

## 6. Scan-failure handling

| Case | Result |
|---|---|
| Broken `.tf` + `--strict` | **exit 2**; stderr names the file (`failed: …/broken/main.tf (… unbalanced braces …)`) and the summary warns the scan is incomplete. Log: `raw/phase9/logs/strict_broken_file.log` ✅ |
| Broken `.tf` without `--strict` | exit 0 (0 findings from 0 parsed files); the failure is recorded as an `error` diagnostic **and** in `scan_completeness.files[]` with `status: "failed"` + reason ✅ — but a pipeline gating only on the exit code would pass. **Recommendation: always use `--strict` in CI** (the shipped workflows don't set it). |
| Report write failure (disk full mid-write, observed when /tmp filled) | **exit 2** (`report error`) — fail-closed ✅ |

## 7. Large repo + repeatability

Synthetic repo: 500 `.tf` files (250 violating + 250 compliant), scanned twice
in pipeline fashion (`--format=json --fail-on=high`):

- Files discovered: 500; findings: **4,002** both runs; exit 1 both runs.
- **Byte-identical output files** (5,679,248 bytes; SHA-256 `fb21ad98…` both
  runs); identical finding sets. Scan time ~1 s.
- Log: `raw/phase9/logs/repeatability.log`.

The scanner is fully deterministic for a given binary + tree.

### 7.1 Notable finding: the committed `aegis` binary is stale

While validating, two fresh builds of HEAD (one from the working tree, one
from a clean clone of `0c28621`) both reported **5,308** findings on the
self-scan, while the **committed `aegis` binary reported 5,047** — a 261
finding delta, dominated by AEGIS-AWS-445 (S3 logging). Root cause: the tracked
binary was last committed in `0262005`, three commits behind HEAD, predating
the D1/D2/D3 demo-defect fixes (`0c28621`) that changed rule behavior. This is
**not** a determinism bug (same binary + same tree ⇒ byte-identical results,
§7) — it is a stale checked-in artifact. **CI implication: always `go build`
from source in the pipeline (as both tested workflows do); never gate on the
committed binary.** Consider either refreshing the committed binary on rule
changes or removing it from version control.

## 8. GitLab CI

Tested file: `raw/phase9/.gitlab-ci.yml` (valid YAML; `golang:1.25` image;
script steps executed verbatim in order via `simulate_gitlab.sh`; log:
`raw/phase9/logs/gitlab_sim_run.log`):

| Step | Result |
|---|---|
| YAML validation | PASS (image, script, `artifacts.reports.sarif`, `allow_failure: false`) |
| `go build -o aegis ./cmd/aegis` | OK |
| `aegis scan . --format=sarif --fail-on="$AEGIS_FAIL_ON"` | exit 1 (gate fails as designed) |
| SARIF validation | schema PASS (5,047 results — same >5,000 note as §2.3 applies to GitHub; GitLab's `reports:sarif` has no such documented cap) |
| Artifact collection | file exists and is the validated SARIF (3.5 MB) |

**Design decision — `reports:sarif`, not `reports:sast`:** recent community
evidence (including a 2026-08 correction of a wrong SARIF-as-`sast` example)
indicates `artifacts:reports:sast` expects GitLab's own security-report JSON
schema, which `aegis --format=json` does **not** emit; GitLab ingests SARIF via
the dedicated `reports:sarif` type (Ultimate-only for the Vulnerability
Report/MR security widget — on other tiers the file in `artifacts:paths`
remains downloadable and the exit-code gate still works). The tested config
therefore declares `reports: { sarif: aegis.sarif }` plus `paths` with
`when: always`.

**Docs caveat (for maintainers):** the `docs/CI_INTEGRATION.md` GitLab example
points `artifacts: reports: sast:` at `aegis.json` (aegis's native JSON, not
the GitLab SAST schema) with a comment claiming "SARIF also accepted". That
example will not populate GitLab vulnerabilities as written; recommend
replacing it with the tested config above.

## 9. Raw artifacts

All under `docs/audit/raw/phase9/`:

| File | Purpose |
|---|---|
| `aegis-demo.yml` | Tested GitHub Actions workflow (consumer pattern) |
| `aegis-selfscan.yml` | Shipped `examples/github-actions/aegis.yml`, verbatim |
| `.gitlab-ci.yml` | Tested GitLab CI config |
| `validate_sarif.py` | SARIF 2.1.0 schema + GitHub-acceptance validator used by both workflows |
| `simulate_github.sh` / `simulate_gitlab.sh` | Step-by-step simulated runners (deltas labeled per step) |
| `logs/gh_consumer_run.log` | Consumer pipeline run (exit 1, SARIF PASS) |
| `logs/gitlab_sim_run.log` | GitLab job run (all script steps verbatim) |
| `logs/exitcode_matrix.log` | 8/8 exit-code cases |
| `logs/baseline_test.log` | Baseline capture/suppress/expiry/removal + fingerprint stability |
| `logs/strict_broken_file.log` | `--strict` failure names the file |
| `logs/repeatability.log` | 500-file double scan, identical SHA-256 |
| `samples/demo_consumer.sarif` | Validated 421-result SARIF from the consumer run |
| `samples/baseline_v1.json`, `samples/baseline_v2_expiry.json` | Baseline formats exercised |

## 10. Summary verdicts

- **GitHub Actions:** SIMULATED (no Docker daemon for `act`; all aegis
  commands ran for real). SARIF is schema-valid and GitHub-acceptable for the
  consumer workflow; the shipped self-scan example exceeds GitHub's 5,000-result
  cap on this fixture-heavy repo — scope the scan or document the cap.
- **Exit codes:** 8/8 match the documented contract.
- **Baselines:** capture → suppress-new-only → expiry → removal all behave per
  spec; fingerprints stable across runs.
- **Failure handling:** `--strict` + broken file → exit 2 naming the file;
  without `--strict` the diagnostic is recorded but the exit code stays 0 —
  use `--strict` in CI.
- **Repeatability:** 500 files, two runs, byte-identical output.
- **GitLab CI:** SIMULATED (no live runner); YAML valid, script steps pass
  verbatim; config uses `reports:sarif` (correct type for SARIF); the
  `docs/CI_INTEGRATION.md` GitLab example needs correction.
- **Two findings for maintainers:** (1) the committed `aegis` binary is 3
  commits stale vs HEAD — always build from source in CI; (2) consider adding
  `--strict` to the shipped workflow examples.
