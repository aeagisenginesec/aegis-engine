# 17. Full-Feature Test + Audit (2026-10-14)

**Tree:** `~/workspace/aegis-engine`, branch `mission/gap-userdata-eol-image`, HEAD `e589088`.
**Method:** three parallel audit tracks (adapters / CLI+robustness / rule packs) plus coordinator-applied fixes.
Nothing committed. The multi-cloud fixture and `docs/audit/raw/` were read/scanned, never modified.
No rules deleted or merged to reduce counts. No count-tuning. No precision/recall claims
(no ground-truth labels exist beyond the quality gate's own labeled set).

## 1. Adapters — all 9 PASS

| Adapter | Vuln fixture | Secure fixture | Malformed input | Verdict |
|---|---|---|---|---|
| terraform | AWS-002/004/104 fire | only justified hygiene | broken HCL→error diag; 600-deep→honest depth error; NUL→hard error; exit 2 under `--strict` | PASS |
| planjson | same delta as terraform | same | invalid/empty/NUL JSON→honest error; 500-deep→warning, no stack blowup | PASS |
| cloudformation | same delta | same | broken YAML→error; NUL rejected; empty→falls through honestly | PASS |
| manifests (K8s) | privileged Deployment→10 K8S findings | fully hardened workload→**zero findings, exit 0** | broken YAML/NUL→errors; unknown kinds modeled honestly | PASS |
| dockerfile | 13 DOCKER findings | 6 justified hygiene residuals | garbage+NUL→null-bytes warning (item6b); empty→clean | PASS |
| compose | COMPOSE-001/007/008 fire | explicit non-root user + read_only→**zero findings** | broken YAML→error diag; empty→warning | PASS |
| bicep | expected AZR/AZURE fire; param resolution works | justified residuals only | broken→warning; empty→0/0 | PASS after fix (see §5.1) |
| arm | same as bicep | same | broken JSON/NUL→error diags; immune to NUL class (Go decoder rejects) | PASS |
| pulumi | open SG + public bucket fire | justified residuals only | honest warnings verified for TS/JS, Python, Go, .NET, Java programs; `runtime: yaml` never warns | PASS after fix (see §5.2) |

**New adapter tests:** `internal/adapter/manifests/vuln_secure_audit_test.go`
(`TestAuditPrivilegedContainerSurvives`, `TestAuditHardenedWorkloadAttributes` — both PASS).

## 2. CLI surface — PASS

Complete inventory verified against `cmd/aegis/main.go` + `serve.go` (not assumed):

| Command | Flags (all verified to parse and act) |
|---|---|
| `scan <dir>` | `--format` (text\|json\|sarif), `--rules`, `--advisories`, `--baseline`, `--baseline-out`, `--compliance`, `--custom-rules`, `--config`, `--exclude`, `--attack-paths`, `--max-file-size`, `--timeout`, `--strict`, `--fail-on` |
| `fix <dir>` | `--apply`, `--force`, `--rule`, `--format` (text\|json) |
| `serve` | `--addr` (default `127.0.0.1:8734`), `--auth-token` (+ `AEGIS_SERVE_TOKEN` env) |
| `quality-gate` | `--format` (text\|json), `--bench-dir`, `--corpus-dir` |
| `doctor` | none (7 self-checks) |
| global | `--version` / `-v` / `version`, `--help` / `-h` / `help` |

- **Help accuracy:** every documented flag exists; every existing flag is now documented
  (fixed: `--attack-paths` was working but undocumented — see §5.4). No per-subcommand help
  (`scan --help` prints generic usage, exit 0) — cosmetic, unchanged.
- **Exit codes:** 0 = clean, 1 = findings reported, 2 = usage/scan error — verified across a
  17-case matrix (nonexistent path→2, unknown flag→2, `--strict` with parse failures→2,
  `fix` dry-run 0/1/2, `doctor` 0/1, `serve` bad bind→1, quality-gate 0/1/2,
  `--fail-on=critical` trips only on CRITICAL).
- **Formats:** `--format=json` parses, envelope carries `aegis_version: "2.0.0"`, findings carry
  `rule_id`/`severity`/`evidence.span`; `--format=sarif` is valid SARIF 2.1.0 with zero orphan
  `ruleId`s (every result has matching `tool.driver.rules` metadata); text headers match
  `^SEV RULEID file:line — title`.
- **`--version`:** `aegis 2.0.0` (build/commit `unknown` without ldflags stamps — expected).
- **`serve`:** loopback `GET /v1/health`→200 `{"status":"ok","version":"2.0.0"}`;
  `POST /v1/scan`→200 with findings; garbage→400; unknown route→404; wrong method→405;
  `--auth-token`→401 without / 200 with `Bearer`; non-loopback bind prints no-auth WARNING.
  Started, curled, stopped cleanly.
- **`quality-gate`:** all 5 gates PASS (see §6).

**New CLI tests:** `cmd/aegis/cli_audit_test.go` (8 tests: version stamp, help↔flags both
directions, 17-case exit-code matrix, JSON/SARIF/text validation, determinism, max-file-size cap),
`cmd/aegis/scan_robustness_test.go` (3 tests incl. 9 adapters × 5 adversarial cases = 45 subtests).

## 3. Rule packs — sampling audit

Sampled per pack (implementations read, traced against vulnerable + secure fixtures):

| Pack | Sampled | Defects found |
|---|---|---|
| alibaba | all 12 (ALI-001..012) | 1 fixed: ALI-009 unknown-value contract violation (§5) |
| oci | all 8 (OCI-001..008) | 1 fixed: OCI-006 severity Medium→High (§5) |
| supplychain | all 9 (SC-001..009) | none (SC-003/SC-008 base64 miss noted, not changed — see below) |
| custom | engine semantics (8 operators, path resolution, compile-time validation) | none — clean |
| terraform | all 8 (TF-001..008) | none (TF-003 `version="*"` miss noted, not changed) |
| compose | all 8 (COMPOSE-001..008) | 1 fixed: COMPOSE-007 false positive (§5) |
| docker | 14/37 | none (DOCKER-012 `sudo` inconsistency noted, not changed) |
| k8s | 12/32 incl. new K8S-028..032 | none — 028..032 verified firing + quiet correctly |
| aws | 12/474 | none in sample |
| azure | 6/284 | none in sample |
| gcp | 6/280 | none in sample |

**Duplicates investigated — all legitimate layering, none removed:**
- DOCKER-025 vs 036 (base-image-is-toolchain vs RUN-installs-build-tools — distinct signals)
- AWS-328 vs 331 (inline `ingress` on `aws_network_acl` vs standalone `aws_network_acl_rule` — distinct resource types)
- K8S-002/004/019 vs 028/029/030 (explicit-misconfig High vs missing-hardening Medium — intentional, documented in `k8s3.go`)
- SC-005 vs SC-006 (`inline` remote-exec vs `command` local-exec — probe-verified independent)
- SC-003 vs AWS-686/687 (pipe-to-shell vs secrets-in-user_data — distinct conditions)

**Unresolved (reported, not changed — outside the four defect categories or count-tuning risk):**
- TF-003 misses `version = "*"`.
- SC-003/SC-008 regex raw `user_data_base64` instead of decoding (no FP possible; fixing adds findings).
- DOCKER-012 lacks SC-003's `(sudo\s+)?` alternative (misses `curl … | sudo bash`).
- OCI-004 also fires on compartment-scoped `manage all-resources` (judged intended).
- ALI-005 `max_password_age=0` fires while absent is quiet (defensible either way).

## 4. Robustness — PASS

- **45 adversarial subtests** (9 adapters × empty / 4 KiB binary garbage / truncated doc /
  deep nesting / ~2 MiB single line), each with 30 s watchdog + panic recovery: **no panics,
  no hangs** (worst case 0.22 s).
- **Determinism:** same tree 5× → byte-identical stdout for text, JSON, and SARIF.
- **Over-cap:** `discovery.MaxFileBytes = 10 MiB` (also 256 MiB total, 20k files,
  `--max-file-size` override); over-cap files are skipped **with** an explicit diagnostic and a
  `scan_completeness` entry — never silent (pinned by test).
- **Unreadable inputs:** single unreadable *file* → honest error diagnostic + "incomplete scan"
  warning (exit 0, exit 2 under `--strict`); unreadable *root directory* → now a hard discovery
  error, exit 2 (fixed — see §5.3; previously a silent `0 findings` fail-open).

## 5. Fixes made (all uncommitted)

### 5.1 BICEP-001 (new diagnostic behavior): NUL-byte finding suppression — FIXED
`internal/adapter/bicep/bicep.go` — a NUL byte inside a Bicep string literal was silently kept,
so sentinel comparisons (`'*'`, `'0.0.0.0/0'`) failed and findings vanished with zero diagnostics
(repro: NSG `sourceAddressPrefix: '<NUL>*'` → 0 findings vs 4 without the NUL). The adapter now
strips NUL bytes with a `bicep: … contains null bytes; stripped before parsing` warning
(same convention as the dockerfile adapter). Test `TestAuditNulByteEmitsDiagnostic` un-skipped → PASS.

### 5.2 PULUMI-001 (new diagnostic behavior): untyped `resources:` entries silent-zero — FIXED
`internal/adapter/pulumi/pulumi.go` — a `Pulumi.yaml` whose `resources:` entries lack `type:`
produced zero resources with zero diagnostics (the entry became a phantom `pulumi_` type no rule
matches). The adapter now warns naming the entry
(`pulumi: resource "weird" has no type: field; skipped (entry is not analyzable)`).
Test `TestAuditUntypedResourcesWarn` un-skipped → PASS.

### 5.3 DISCOVERY-001: unreadable root directory silent fail-open — FIXED
`internal/discovery/discovery.go` — `aegis scan` on a `chmod 000` directory printed
`resources: 0, findings: 0`, exit 0, no diagnostic, contradicting the documented contract
("a discovery hard failure is returned as an error (exit 2)"). A root-level walk error is now a
hard discovery error → `aegis: scan error: discovery: cannot read scan target …`, exit 2.
Mid-walk unreadable *files* keep the lenient behavior (skipped with honest diagnostics).
Verified end-to-end as the `nobody` user (root bypasses permission checks).
New tests: `internal/discovery/root_unreadable_audit_test.go` (skip when euid == 0, as here).

### 5.4 CLI-001: `--attack-paths` undocumented — FIXED
`cmd/aegis/main.go` usage text now documents `--attack-paths`; the `knownGap` carve-out was
removed from `TestCLIAuditHelpDocumentsEveryFlag`, which now enforces the total contract.

### 5.5 AEGIS-COMPOSE-007: false positive — FIXED
`internal/rules/compose/compose.go` — fired when `user:` was *absent*, violating the pack's own
contract ("missing or unknown values never produce a finding") and a factually wrong description
(without `user:` the container runs as the image's USER, which the scanner cannot see — not
necessarily root). Now: absent/unknown → silent; only explicit `root`/`0` fires. Description
rewritten. Tests updated + 2 new; the two `container-compose` parity fixtures re-recorded
(secure 1→0 findings, vuln 5→4).

### 5.6 AEGIS-ALI-009: unknown-value contract violation — FIXED
`internal/rules/alibaba/alibaba2.go` — with `type=ingress`, `cidr_ip=0.0.0.0/0` and
`policy` present-but-unresolved (`var.policy`), the rule fired, violating the file's own
"present-but-unresolved values yield NO finding" contract (`type`/`cidr_ip` already returned nil
on unknown; `policy` was the odd one out). Now returns nil on unknown `policy`. Tests:
`TestALI009_UnknownPolicyQuiet`, `TestALI009_AbsentPolicyFires`.

### 5.7 AEGIS-OCI-006: severity mismatch — FIXED
`internal/rules/oci/oci.go` — Autonomous Database without customer-managed KMS was Medium while
OCI-001 (bucket) and OCI-005 (volume) are High for the identical "no `kms_key_id`" condition and
identical risk statement. Now High. Test `TestOCI_CMEKRulesShareSeverity` pins all three at High.

## 6. Verification

| Check | Result |
|---|---|
| `go test ./...` | **green — 32 packages, 0 FAIL** |
| `go test -race` (bicep, pulumi, discovery, cmd/aegis) | clean |
| `aegis quality-gate` | **5/5 PASS** — precision 100% (355 tp/0 fp), recall 100%, rule-coverage 358/358, perf p95 35.5 ms (≤500 ms), parser-safety 15/15 |
| Multi-cloud benchmark | **122 findings** (5 critical / 39 high / 46 medium / 32 low) — holds on the release commit |
| Determinism | 5/5 byte-identical (json, text, sarif) |
| `go vet` / `gofmt` | clean on touched packages |

## 7. Not covered and why

- Forced `--timeout` path: flag accepted and wired (exit 2 on timeout), but scans complete in
  ~20 ms — no real timeout triggered without an artificially slow scan.
- `fix --apply` write path: deliberately not exercised (mutates the target tree); dry-run, JSON
  validity, and exit codes verified.
- `quality-gate --format=json` full run: text run fully verified; JSON smoke-tested only.
- `AEGIS_SERVE_TOKEN` env auth: `--auth-token` flag verified end-to-end; env var feeds the same
  variable, not separately exercised.
- Serve concurrency/DoS bounds (16 slots, 32 MiB cap): code-reviewed only, not load-tested.
- Packs: aws/azure/gcp sampled (12/6/6 of 474/284/280), not exhaustively traced — the multi-cloud
  audit (report 15) and follow-up (report 15 §16) already traced 122+ findings against rule code.

## 8. Remaining limitations

- Pulumi Python/Go/.NET/Java programs are detected and warned, not analyzed (TypeScript programs
  are parsed by the in-tree adapter).
- EOL OS tables (AWS-856, GCP-294) are static and need maintenance.
- GCP-293 misses interpolations inside metadata **maps**.
- AWS-103's subnet assumption is unstated in its evidence text.
- TF-003 severity wording; span-remap edge cases; parser repair is intentionally bounded.
- `fix --apply` is intentionally conservative (IAM/networking blocked without `--force`).

## 9. Environment notes

- A sandbox restart mid-audit wiped `/tmp` (binaries rebuilt; no evidence lost).
- File modifications seen mid-audit in `internal/rules/{compose,alibaba,oci}` were initially
  attributed to a concurrent agent; on reconciliation they match this audit's own packs-track
  fixes (COMPOSE-007, ALI-009, OCI-006). The rebuilt root `aegis` binary remains unattributed.
- Two audit tests were written skipped-then-unskipped as their gaps were fixed in this run
  (bicep NUL, pulumi untyped); no skipped tests remain from this audit.

## Diff stat (uncommitted)

- Modified (13 files, +137/−34): `cmd/aegis/main.go`, `internal/adapter/bicep/bicep.go`,
  `internal/adapter/pulumi/pulumi.go`, `internal/discovery/discovery.go`,
  `internal/rules/alibaba/alibaba2.go`, `internal/rules/compose/compose.go`,
  `internal/rules/oci/oci.go` (+ their `_test.go` files),
  `benchmark/parity/fixtures/container-compose/{secure,vuln}/compose/expect.json`;
  plus the rebuilt root `aegis` binary (unattributed).
- New (6 test files): `cmd/aegis/cli_audit_test.go`, `cmd/aegis/scan_robustness_test.go`,
  `internal/adapter/bicep/nul_suppression_audit_test.go`,
  `internal/adapter/manifests/vuln_secure_audit_test.go`,
  `internal/adapter/pulumi/untyped_resources_audit_test.go`,
  `internal/discovery/root_unreadable_audit_test.go`.
- This report: `docs/audit/17_FULL_FEATURE_AUDIT.md`.
