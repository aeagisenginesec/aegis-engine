# ITEM 6 — Performance, Scale & Reliability

Date: 2026-10-13. Branch: `mission/top-tier-validation`. Binary: `aegis 1.0.0`, **1151 rules loaded**
(1151 here vs 1185 in the prior Phase 6 report — different tree state, do not conflate).

## 0. How to read this report

- All numbers were measured on a **shared, moving tree**: six parallel workers editing the same
  working tree during this task. Numbers describe the tree as of each measurement, not a frozen
  commit. Where another worker's in-flight change affected a result, it is called out.
- **Wall times from the second perf campaign are contaminated** (box load average 11–16, six
  workers fuzzing/testing concurrently). CPU time and peak RSS are the robust metrics there.
- Cold-cache (post-reboot / spinning-disk) numbers were **not** measured.
- Total-cap / MaxFiles-cap behavior was **not** exercised (would need 256 MiB total or 20,000 files).
- Fuzz execution counts prove breadth, not safety. No claim of parser safety is made from counts
  alone; the safety argument is the combination of coverage, invariants, minimized reproductions,
  and the silent-suppression audit (§6).

## 1. Methodology & machine

- Machine: 2 vCPU, 7.9 GB RAM, Linux `htch-runtime 7.0.0-39-generic`, Go 1.25.4
  (`~/gosdk/go/bin/go`). `/tmp` is a 512 MB tmpfs (filled twice during this task by concurrent
  workers — see §8).
- Corpora: deterministic generator (seed 42), `corpus-small` (13 files), `corpus-medium`
  (203 files), `corpus-large` (2003 files). Mix cycles 9 kinds: TF, CFN YAML, K8s YAML,
  Dockerfile, Compose, Bicep, ARM JSON, Pulumi YAML, Plan JSON. Every 20th TF file is a module
  caller; one shared `modules/net` module; one 200-statement IAM policy file (`bigpolicy.tf`);
  one 20-deep nesting file.
- **Corpus caveats (do not present as a pure real-repo mix):** resource yield is low. Pulumi
  files are named `Pulumi_XXXX.yaml`, but the Pulumi adapter requires the literal `Pulumi.yaml`,
  so most Pulumi corpus files are not claimed by the Pulumi adapter. YAML dispatch order affects
  which adapter claims `.yaml` files. Corpus composition and per-adapter yield must be disclosed
  alongside any throughput claim.
- Perf harness: CLI `--format=json`, warm OS page cache. "Cold" = first exec of the binary
  (no `drop_caches` — same limitation as the prior report). No cold-start penalty was visible
  (run 1 inside the warm distribution; small run 1, 726.0 ms, was the fastest).
- Adversarial battery: 74 hand-built cases (`gen_adv.py` + `gen_adv2.py`), each run in isolation
  with a timeout (20 s first runs, 60 s final run). Cases cover malformed inputs, cycles,
  deep nesting, huge strings, null bytes, invalid UTF-8, billion-laughs-style expansion.
- Fuzzing: Go `go test -fuzz` per parser, seeds = curated adversarial inputs (§5). Invariant:
  no panic/hang; a hard error must never accompany returned resources.
- Determinism: repeated runs byte-compared by SHA-256 of stdout. Concurrency: 8 parallel
  scans of the large corpus, hashes compared.

## 2. Performance

### 2.1 Before fixes (first campaign, 7 runs small/medium, 5 runs large)

| Corpus | Files | Resources | Findings | p50 | p95 | p99 | Min | Max | Mean CPU | Peak RSS |
|---|---|---|---|---|---|---|---|---|---|---|
| small | 13 | 17 | 127 | 874.4 ms | 982.5 ms | 983.1 ms | 726.0 ms | 983.3 ms | 0.89 s | 23,264 KB |
| medium | 203 | 249 | 2320 | 1117.8 ms | 2775.7 ms | 3107.0 ms | 961.9 ms | 3189.8 ms | 1.13 s | 41,680 KB |
| large | 2003 | 2439 | 23120 | 1876.6 ms | 1964.6 ms | 1972.4 ms | 1774.5 ms | 1974.3 ms | 2.30 s | 204,244 KB |

Throughput at p50: medium ~181.6 files/s, ~222.8 resources/s; large ~1067.3 files/s,
~1299.7 resources/s. RSS/CPU from single `/usr/bin/time -v` runs (wall times in those runs
were contaminated by sibling load and are not quoted).

### 2.2 After fixes (second campaign, 5 runs each — wall times contaminated, see §0)

| Corpus | Files | Resources | Findings | p50 (wall) | Mean CPU | Peak RSS |
|---|---|---|---|---|---|---|
| small | 13 | 17 | 128 | 14,951 ms (contaminated) | 1.97 s | 24,328 KB |
| medium | 203 | 249 | 2321 | 20,217 ms (contaminated) | 2.36 s | 35,916 KB |
| large | 2003 | 2439 | 23121 | 25,386 ms (contaminated) | 3.40 s | 182,388 KB |

### 2.3 Before/after analysis

- **Findings +1 in every corpus (127→128, 2320→2321, 23120→23121).** Verified: the extra
  finding is `AEGIS-AWS-677` on `bigpolicy.tf` (scan of `bigpolicy.tf` alone: 1 finding,
  0 diagnostics). The TF lenient-recovery fix (§4.6) restores a real detection the old
  256-iteration cap dropped. This is a detection improvement, not noise.
- **CPU +~1.1 s, constant across corpora** (small +1.08 s, medium +1.23 s, large +1.10 s).
  The delta is the same absolute cost in all three corpora because it is the same file:
  recovering `bigpolicy.tf` now costs ~400 HCL re-parses. That is the price of recovery;
  it is bounded by the 16 MiB repair budget (§7) and does not scale with corpus size.
- **RSS within run-to-run noise** (large 204 MB → 182 MB). Do not claim an improvement or a
  regression; different runs, different tree states.
- **No scaling regression from the fixes.** The fixes touch per-file parse paths (bounded
  budgets), not the engine's per-resource correlation work. The prior scaling fix
  (`SCALING_RESOLUTION.md`, quadratic→~1.25 exponent) is untouched.

## 3. Reliability

### 3.1 Determinism & concurrency

- Repeated runs: byte-identical stdout across 7/7 small, 7/7 medium, 5/5 large runs
  (identical invocation). Post-fix re-check: 5× small scans → 1 distinct SHA-256.
- Concurrent scans: 8 parallel scans of the large corpus → identical hash
  `9a40180d…247` (same relative target). An absolute-path single scan differs only because
  the `target` string is embedded in the JSON output — compare hashes only within identical
  invocations.

### 3.2 Adversarial battery (74 cases, final run)

**Zero crashes, zero hangs, zero timeouts** (60 s per-case timeout). Every case either
produces findings, a diagnostic, or is a legitimately empty/resource-less input (§6).

Notable battery results:

| Case | Before | After |
|---|---|---|
| CFN YAML alias cycle (`BucketName: &a [*a]`) | **Stack overflow, process killed (exit 2)** | 0.03 s, warning, 6 findings |
| Pulumi YAML alias cycle | **Stack overflow / OOM-kill** | 0.13 s, warning, 6 findings |
| Pulumi variable reference cycle (`a: ${b}, b: ${a}`) | **Stack overflow (exit 2)** | 0.03 s, warning, 6 findings |
| ARM billion-laughs (`v_i = concat(v_{i-1}, v_{i-1})`, chain 22) | **17.59 s** (~4× per +2 levels, 2²² leaf evals from a ~2 KB file) | **0.08 s** |
| K8s valid doc + malformed later doc | Valid Pod's findings silently dropped (0 findings) | Valid Pod survives (6 findings) + error diagnostic |
| TF sloppy 200-statement policy | 0 findings, error diag | Recovers: 1 finding, 0 diags (15.4 s wall under load) |
| TF sloppy 2000-statement policy | Would hang past 20 s (unbounded repair loop) | Terminates (~13–22 s wall under heavy sibling load, ~3 s CPU) with error diag; documented unrecoverable fallback |
| Discovery over-cap file (11 MB, default 10 MiB cap) | **0 findings, no diagnostic at all** | Warning diagnostic naming file + cap; file listed as `skipped` |
| CFN billion-laughs diamond (8 levels × 8) | Would blow up exponentially | Budget warning, 1.7 s, 6 findings |
| Pulumi billion-laughs diamond (9 levels × 8 = 134M walks) | Would blow up exponentially | Budget warning, terminates, 6 findings |
| K8s billion-laughs (6 levels × 8) | "excessive aliasing" error (old code) | Materializes in 3.0 s (Item 5's 2M-node budget), 0 findings, 0 diags |
| Bicep `var x = [[[ ~[[[[[` | **Infinite loop / OOM hang** (fuzzer-found) | Completes instantly (sibling's progress guard, §4.8) |

Also verified clean: null bytes, invalid UTF-8, empty files, deep nesting within caps,
huge strings (TF 5 MB string 0.72 s; Dockerfile 5 MB line 2.48 s; TF 200k comment lines
1.58 s), module cycle, TF var cycle, ARM var cycle, Bicep deep parens/array/ternary,
CFN deep intrinsic/mapping, plan JSON deep nest (Go JSON max-depth diagnostic), K8s deep
nest (YAML max depth 10000 diagnostic), K8s 10k documents (1.59 s).

### 3.3 Over-cap end-to-end (CLI, final binary)

11,000,064-byte `big.tf` + one small file: `files_discovered = 2`, one `skipped`, one
warning diagnostic: `discovery: skipped …/big.tf: file size 11000064 bytes exceeds
per-file cap 10485760 bytes (--max-file-size)`.

## 4. Crashes / silent-suppression found and fixed

### 4.1 CFN YAML alias cycle — stack overflow (FIXED, this task)

`BucketName: &a [*a]` → `resolveValue` looped AliasNode → Sequence → AliasNode until the
goroutine stack exceeded 1 GB. Root cause: CFN decodes into `yaml.Node`, which does **not**
get yaml.v3's alias safeguards. Fix (`cloudformation/cfn.go`, `intrinsics.go`): alias
cycle guard (`aliasActive map[*yaml.Node]bool`) + alias expansion budget (`maxAliasExpansions
= 100000`, single warning on exhaustion); cyclic/over-budget values become Unknown.
Regression: `cloudformation/item6_test.go` (alias cycle: 2 resources survive + cycle diag;
alias budget: 8 levels × 8, budget warning, resource survives).

### 4.2 Pulumi YAML alias cycle — stack overflow / OOM (FIXED, this task)

Same `&a [*a]` shape. Fix (`pulumi/pulumi.go`): alias cycle guard + `maxPulumiWork =
20000000` work budget in `value()` (needed because `${...}` re-walks multiply work; an
alias budget alone would not bound `${}` diamonds). Cycle/budget → Unknown + single warning.
Deliberately did **not** memoize Pulumi var values: cached `ir.Value` maps are mutable and
`flattenNestedProperties` merges into them, risking cross-resource contamination.
Regression: `pulumi/item6_test.go` (alias cycle, var cycle, var-chain resolves
`b: ${a}`, `bucket: ${b}` → `hello` Known).

### 4.3 Pulumi variable reference cycle — stack overflow (FIXED, this task)

`a: ${b}, b: ${a}` → `scalar → value → resolveRef` loop. Fix: `resolving map[string]bool`
cycle guard in `resolveRef` (set/delete around `p.value()`), warning + Unknown.
Regression: same file as §4.2.

### 4.4 ARM variable-chain exponential re-evaluation — DoS (FIXED, this task)

`v_i = concat(v_{i-1}, v_{i-1})`: no memoization, each `variables()` lookup re-evaluated the
whole subtree. Pre-fix: chain 12 → 0.08 s, 16 → 0.54 s, 18 → 0.69 s, 20 → 2.91 s,
22 → 17.59 s (doubling per level). Fix (`arm/arm.go`): `varCache` memoization with a
cycle-aware cache rule — cache only if `cycleHits` (counter, not bool) is unchanged since
evaluation started, so values computed while a dependency was in-progress (which
`coalesce()` would corrupt by skipping Unknowns) are never cached. Plus
`maxConstructedString = 1<<20` (1 MiB) caps on `concat`/`format`/`replace`/`join`
amplification (literals from the file are unaffected — bounded by the file-size cap).
Post-fix: chain 22 → 0.08 s; chain 30 falls back to the raw expression as the name.
Regression: `arm/item6_test.go` (memoized chain v16 exact length `8×2¹⁶ = 524288`; chain
cap v30 fallback; cache-cycle-poisoning test proving the guard reproduces no-cache
evaluation order; direct var cycle). Two test bugs of mine were found and fixed during this
work (an 8 GiB allocation in the cap test; a wrong poisoning expectation — cyclic variables
have no unique fixed point, the guard must reproduce no-cache behavior, not freeze first
evaluation order). The sticky-bool → counter change was a real code bug the poisoning test
caught.

### 4.5 Manifests (K8s) multi-doc: valid doc findings dropped on later bad doc — silent suppression (FIXED, this task)

A valid privileged Pod + a malformed second document → 0 findings, only an error diagnostic.
Root cause: `manifests.decode()` returned `nil` on any decode error, discarding
already-decoded docs. Fix (`manifests/manifests.go`): both error paths return the docs
decoded so far; only the failing document is lost; the error diagnostic is still emitted.
Regression: `manifests/item6_test.go` (valid Pod + malformed second doc → Pod survives +
error diag).

### 4.6 Terraform lenient separator recovery: cap + unhandled separators — policy silently dropped (FIXED, this task)

Probe: HCL `ParseConfig` returns exactly **1** separator diagnostic per parse. The old
256-iteration cap could not recover a 200-statement sloppy policy (~2 repairs/statement:
100/120 statements recovered, 140+ failed). Separately, recovery stalled at the first tuple
boundary: the parser reports `Missing item separator` (tuple) and `Missing argument
separator` (call), which `separatorRepairs` did not handle — the loop returned 0 repairs and
fell back to a partial parse. Fix (`terraform/terraform.go`): iteration cap 256 → 2048;
`separatorRepairs` handles attribute + item + argument separators (all insert `,` at
`Subject.Start.Byte`); cumulative re-parsed-bytes budget `maxLenientRepairBytes = 16<<20`
(16 MiB: a 200-statement sloppy policy needs ~7 MiB to recover; a 117 KiB file with 2000
sloppy statements aborts after ~136 iterations instead of hanging; a 10 MiB file aborts
after ~2 iterations). Regression: `terraform/item6_test.go` (sloppy 100-statement policy
recovers, policy Known, no error diag; `PreValidate` honors `--max-file-size` override).
Note: the 100-statement test takes ~4.5 s (~300 reparses) — expected, do not "optimize"
by shrinking it. The 16 MiB budget replaced an initial 32 MiB after the 2000-statement case
timed out at 20 s under load.

### 4.7 Discovery over-cap silent drop + TF cap mismatch (FIXED, this task)

Prior Phase 6 Finding 2 reproduced on this branch: an 11 MB file with the default cap gave
`files_discovered: 0`, 0 findings, **no diagnostic**. With `--max-file-size 12582912` it was
discovered but failed with `terraform: … file exceeds 10 MiB limit` (TF adapter hard cap
ignored the flag). Fix: `discovery/discovery.go` gains `Skipped{Path, Size, Reason}` and
`DiscoverWithReport()` (oversize files recorded with a reason naming the cap; scan-wide cap
hit recorded as a synthetic entry); `cmd/aegis/main.go` `scanFull` emits a warning
diagnostic per oversize file, lists oversize files as `skipped` in completeness, and counts
them in `FilesDiscovered`; `terraform/hardening.go` `PreValidate` uses
`discovery.EffectiveMaxFileBytes()` instead of the constant. Regression:
`discovery/item6_test.go`, `cmd/aegis/item6_test.go` (end-to-end over-cap: diagnostic
mentions `big.tf` + cap, completeness has `big.tf` skipped, `FilesDiscovered == 2`).

### 4.8 Bicep `var x = [[[ ~[[[[[` — infinite loop / OOM hang (FOUND by this task's fuzzer; FIXED by a sibling worker, VERIFIED by this task)

The Bicep fuzz target saved the minimized input (47 bytes: `var x = [[[ ~[[[[[`).
On the pre-guard binary the CLI hung past the 15 s timeout (no output); the fuzz-seed test
ran 76 s then was SIGKILLed (OOM). Root cause: `parseExpr` returns `unknownExpr()` without
consuming input on failure, and `parseArray` looped on the unconsumed `~` forever. The
sibling worker's fix (10-line progress guard in `parseArray`: fail the array when
`parseExpr` makes no progress) landed in the shared tree while this task's fuzz run was
executing. Verified on a fresh binary from the current tree: the input completes instantly
(0 findings, 0 diags). **Not my code — do not attribute the fix to this task.**
Residual observation (not fixed, no resources affected): the malformed `var` is dropped
with no diagnostic. The saved fuzz corpus entry
(`bicep/testdata/fuzz/FuzzItem6Parse/63c8ae091bf56177`) is the regression artifact.

### 4.9 NOT fixed (documented, by design or minor)

- **TF valid-plus-truncated / unbalanced:** a valid resource in the same file yields 0 findings
  because `PreValidate` rejects the whole file (hard error, file marked failed). A diagnostic
  IS present. Fail-fast by design.
- **Dockerfile no-FROM:** 0 findings, 0 diags. A FROM-less Dockerfile yields no resource by
  design; whether it deserves a warning is undecided.
- **Bicep + null bytes:** an initial 0-finding result was an artifact of an empty file caused
  by `/tmp` disk-full during probe setup. Correct re-run: 19 findings — no silent suppression.

## 5. Parser safety: coverage + fuzz per parser

Statement coverage from unit tests + fuzz seeds (`go test -coverprofile`). This is
coverage of the package's statements, not a safety proof.

| Parser | Package coverage | Key functions | Fuzz execs (approx) | Crashes |
|---|---|---|---|---|
| Terraform HCL | 79.7% | `lenientParseConfig` 91.7%, `separatorRepairs` 80.0%, `ParseModule` 81.9% | 21,232 (existing `FuzzParseModule`, 243 interesting) | 0 |
| TF plan JSON | 96.8% | — | ~44k, 46 interesting | 0 |
| CloudFormation JSON/YAML | 62.1% | `resolveValue` 87.8%, `resolveIntrinsic` 74.3% | 28,350, 74 interesting | 0 |
| ARM | 54.2% | `evalExpression` 66.7%, `callFunc` **28.6%** | ~41k, 34 interesting | 0 |
| Bicep | 69.3% | — | ~14k, 13 interesting + 1 hang found | 1 hang → fixed (§4.8) |
| Pulumi YAML | 87.0% | — | ~28k, 102 interesting | 0 |
| Dockerfile | 66.5% | — | ~34k, 58 interesting | 0 |
| Compose | 95.9% | — | 70,068, 224 interesting | 0 |
| K8s (manifests) | 73.4% | — | ~12k, 63 interesting | 0 |
| Discovery | 60.4% | — | n/a | 0 |

Total ≈ 295k fuzz executions across 9 parsers. **Zero crashes in Aegis code.**
Two apparent failures were environment artifacts, not bugs:
- A Terraform fuzz run "failed" with `SIGBUS` in `internal/fuzz` shared-memory code while
  `/tmp` was 100% full. Re-run with `TMPDIR` under home: 21,232 execs, clean.
- Two fuzz runs "failed to build" while `/tmp` was full (linker: no space left on device).
  Re-runs with home tmpdirs passed.

**Biggest coverage gap:** ARM `callFunc` at 28.6% — the function-dispatch table is largely
unexercised by unit tests + seeds. The ARM fuzz target does reach it (via mutated
expressions), but per-function fuzz coverage was not measured. Follow-up: add unit tests
driving each ARM function through `callFunc`, or measure fuzz coverage with
`-fuzz` + coverage profiling.

**Fuzz targets added (new files only, existing test files never edited):**
`item6_fuzz_test.go` in cloudformation, pulumi, arm, bicep, manifests, planjson,
dockerfile, compose (invariant: no panic; hard error never accompanies resources).
Terraform already had `FuzzParseModule` — no duplicate added.

## 6. Silent-suppression audit

Rule applied to every 0-findings case in the final 74-case battery: a parse error must
produce a diagnostic, never a silent 0-findings result.

- All 0-findings cases in the final battery have either a diagnostic or are legitimately
  empty/resource-less inputs (empty files, comment-only files, param-only Bicep, var-only
  Bicep, no-FROM Dockerfile, huge-string files with no resources).
- The two silent-suppression bugs found (§4.5 manifests, §4.7 discovery) are fixed and
  regression-tested.
- The one remaining fail-fast loss (TF valid resource in a truncated file, §4.9) carries a
  diagnostic — visible, not silent.

## 7. Explicit limits for unsupported inputs

| Input / behavior | Limit | Behavior past the limit |
|---|---|---|
| Per-file size (default) | 10 MiB (`--max-file-size`) | File listed as `skipped` + warning diagnostic naming file + cap |
| Total scan size | 256 MiB (`discovery.MaxTotalBytes`) | Scan-wide cap recorded (untested — §0) |
| File count | 20,000 (`discovery.MaxFiles`) | Scan-wide cap recorded (untested — §0) |
| TF nesting depth | 50 levels (`MaxNestingDepth`) | Hard error, file failed, diagnostic |
| TF lenient repair iterations | 2048 | Fall back to partial parse + error diagnostic |
| TF lenient repair bytes (cumulative re-parsed) | 16 MiB | Fall back to partial parse + error diagnostic |
| CFN YAML alias expansions | 100,000 | Single warning; remaining alias values Unknown |
| Pulumi evaluation work | 20,000,000 `value()` calls | Single warning; remaining values Unknown (~8 s CPU worst case) |
| ARM constructed strings | 1 MiB (`maxConstructedString`) | Expression falls back / Unknown; literals unaffected |
| K8s converted nodes (Item 5) | 2,000,000 (`maxConvertedNodes`) | Error diagnostic (their budget, not this task's) |
| K8s YAML depth | 10,000 (yaml.v3) | Error diagnostic |
| JSON depth (plan/ARM) | Go `encoding/json` max depth | Error diagnostic |

Recommendations for untrusted input: use `--timeout`; do not rely on budgets alone (many
distinct large ARM variables can still accumulate; Pulumi `${}` diamonds are bounded by
work, not by memory).

## 8. Environment hazards observed (for future missions)

- `/tmp` (512 MB tmpfs) filled twice during this task by concurrent workers, producing false
  results: empty probe files (false 0-finding "Bicep + null bytes" result), linker "no space
  left" failures, and a Go-fuzzer `SIGBUS` from truncated shared memory. Mitigation used:
  `TMPDIR`/`GOTMPDIR` under home for all `go test`/`go build`/`-fuzz` runs.
- A 6-worker shared tree means measurements describe a moving target; another worker's
  in-flight edit broke `cmd/aegis/main.go` once (repaired by them) and landed the Bicep
  guard mid-measurement (§4.8).
- Box load 11–16 during the second perf campaign makes wall times unusable; CPU + RSS
  remain the robust metrics.
- Fuzz corpus entries saved by the fuzzer land in `testdata/fuzz/<Target>/` in the repo;
  the Bicep entry from §4.8 is the only one added by this task's fuzzing.

## 9. Files changed by this task

Modified: `internal/adapter/cloudformation/cfn.go`, `intrinsics.go`;
`internal/adapter/pulumi/pulumi.go`; `internal/adapter/arm/arm.go`;
`internal/adapter/manifests/manifests.go`; `internal/adapter/terraform/terraform.go`,
`hardening.go`; `internal/discovery/discovery.go`; `cmd/aegis/main.go` (scanFull only).
New (tests only): `item6_test.go` in cloudformation, pulumi, arm, manifests, terraform,
discovery, `cmd/aegis`; `item6_fuzz_test.go` in cloudformation, pulumi, arm, bicep,
manifests, planjson, dockerfile, compose. Existing test files never edited; no
`gofmt` of whole files; no git operations performed.
