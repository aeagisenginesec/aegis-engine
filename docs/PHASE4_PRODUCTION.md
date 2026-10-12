# Phase 4: Production Readiness

Hardening Aegis for production use across five workstreams. All verified:
`go build ./...`, `go vet ./...`, `gofmt -l .` clean, `go test -race ./...`
green (22 packages, zero failures).

## 1. Parser Hardening

**New:** `internal/adapter/terraform/hardening.go` — `PreValidate()` runs
cheap structural checks on raw `.tf` source *before* the HCL parser sees it.

| Input | Result |
|---|---|
| Empty file (0 bytes) | Valid — zero resources, no error (explicitly documented) |
| Null bytes | `terraform: <file>: file contains null bytes; not valid UTF-8 HCL` |
| UTF-16 BOM (`FF FE` / `FE FF`) | `terraform: <file>: file appears to be UTF-16 encoded; convert to UTF-8` |
| File > 10 MiB | `terraform: <file>: file exceeds size limit` (reuses `discovery.MaxFileBytes`) |
| Unbalanced braces | `terraform: <file>: unbalanced braces — file may be truncated` |
| Nesting > 50 levels | `terraform: <file>: nesting depth exceeds 50 levels` |

The brace/nesting scan skips string literals, heredocs, and comments
(best-effort; the real HCL parser catches the rest). Every error is prefixed
`terraform:` and names the file. Failures are explicit — never silent clean.

**Fuzzing:** `internal/adapter/terraform/fuzz_test.go` — `FuzzParseModule`
with seed corpus (valid, truncated, binary, null bytes, UTF-16 BOM, 60-level
nesting, 11 MB input, unbalanced braces, empty). Invariant: never panics,
never hangs. Run with `go test -fuzz=FuzzParseModule ./internal/adapter/terraform/`.

**Tests:** `hardening_test.go` covers every failure mode.

## 2. Race & Concurrency Safety

- `go test -race ./...`: **zero data races** across all 22 packages.
- The rule engine (`internal/rules/engine.go`) parallelizes across
  `runtime.NumCPU` workers with strict isolation: each rule writes only its
  own findings slice; the shared resource list is read-only; output is
  deterministically re-sorted. Verified by:
- **New:** `internal/rules/stress_test.go`
  - `TestConcurrentScanDeterminism`: 100 concurrent scans of the same 200
    resources → byte-identical findings hashes every run.
  - `TestConcurrentRegistryReuse`: 32 goroutines × 25 iterations hammering a
    shared registry → no races, no panics.
  - Both pass under `-race`.

## 3. Large Repository Handling

**Measured** (synthetic corpus: 500 `.tf` files, 10,000 resources):

| Metric | Value |
|---|---|
| Scan time | 7.2 s (~1,400 resources/sec) |
| Findings | 100,000 (10 per resource, as expected) |
| Peak RSS | 401 MB (~40 KB per resource) |
| Diagnostics | 0 (no parse failures) |
| Crash/OOM | None |

**New CLI flags:**
- `--max-file-size=N` (scan): per-file byte cap override (default 10 MiB from
  `discovery.MaxFileBytes`). Wired via `discovery.SetMaxFileBytes()`.
- `--timeout=N` (scan): overall scan timeout in seconds (0 = no limit).
  Aborts with exit 2: `aegis: scan error: scan timed out after N seconds`.

Existing discovery caps (10 MiB/file, 256 MiB total, 20,000 files) already
prevent OOM; the new flags give operators control.

## 4. Remediation Safety Validation

**Audit:** all 8 shipped fixers (001, 002, 007–012) verified minimal-diff:
single attribute flips or single block inserts, never reformatting. None
touch IAM or networking resources.

**New:** `internal/remediation/safety.go` — dangerous-resource blocklist:

```go
var BlockedResourceTypes = map[string]bool{
    "aws_iam_policy": true, "aws_iam_role_policy": true,
    "aws_iam_group_policy": true, "aws_iam_user_policy": true,
    "aws_iam_role": true, // trust policy controls role assumption
    "aws_security_group": true, "aws_security_group_rule": true,
    "aws_vpc_security_group_ingress_rule": true,
    "aws_vpc_security_group_egress_rule": true,
    // ... plus NACLs
}
```

`ProposeAll` skips blocked types unless `remediation.AllowBlocked` is set.
CLI: `aegis fix --force` sets it, printing a stderr warning:
`WARNING: --force enables patches on IAM/networking resources. Review every diff before applying.`

**Safety tests** (`safety_test.go`): complex multi-resource file (VPC, SG
with multiple ingress blocks, IAM role+policy, RDS, S3, variables, locals,
dynamic blocks) — every proposed patch re-parses cleanly, the target
resource still exists, and zero patches are proposed for IAM/SG findings
without `--force`.

**Dry-run default:** verified — `aegis fix` without `--apply` writes nothing.

## 5. Regression Suite

**New:** `internal/regression/` — golden-file tests.

- `testdata/`: `s3_insecure.tf`, `sg_open.tf`, `rds_mixed.tf` (realistic
  vulnerable fixtures) + `.golden.json` snapshots of full-pipeline findings.
- Any rule change altering output on these fixtures fails the test with a
  diff — explicit review required.
- Regenerate: `AEGIS_UPDATE_GOLDEN=1 go test ./internal/regression/`.

## 6. `aegis doctor`

New command — binary self-check, exits 0 when healthy:

```
$ aegis doctor
aegis doctor — self-check
  [ok] rule registry: 326 rules loaded
  [ok] parse smoke test: 1 resource parsed, 0 error diagnostics
  [ok] malformed input rejected: truncated HCL returns an error
  [ok] binary input rejected: null bytes return an error
  [ok] rule engine: 8 findings on unencrypted bucket
  [ok] remediation dry-run: 2 patches proposed (no writes)
  [ok] runtime: go go1.25.4, linux/amd64
aegis doctor: all checks passed
```

## Remaining Risks

1. **Fuzzing is seed-only in CI.** `FuzzParseModule` needs sustained
   fuzzing runs (`go test -fuzz`, minutes to hours) to find deep parser
   bugs. Recommend a nightly fuzz job.
2. **`--timeout` is not cancellable mid-flight.** It bounds CLI wait time
   but doesn't interrupt an in-progress scan goroutine (leaks until done).
   Acceptable for CLI use; not suitable for library embedding with strict
   deadlines.
3. **Golden files need maintenance.** Every intentional rule-output change
   requires `AEGIS_UPDATE_GOLDEN=1` + review. Documented, but easy to
   rubber-stamp.
4. **Large-repo memory is linear** (~40 KB/resource). A 100k-resource repo
   would need ~4 GB. The 256 MiB discovery cap bounds *input* size, not
   resource count. Consider streaming findings for very large repos.
5. **`--force` is a footgun by design.** It exists for automation; the
   warning is stderr-only. Consider requiring interactive confirmation
   when stdin is a TTY.
