# Item 6 — Addendum: additional findings & fixes (second Item 6 worker)

**Companion to:** `docs/audit/14_SCALE_RELIABILITY.md` (the sibling Item 6
worker's report). **Do not treat this file as a replacement** — the sibling
report covers the CFN/Pulumi alias-cycle fixes, ARM memoization/caps,
manifests multi-doc fix, TF lenient-recovery fix, and discovery over-cap
fix (§4.1–4.7 there), all of which this run re-verified. This addendum
covers only what the sibling report does **not**: seven additional
bugs found and fixed by this worker (including two more fuzzer-found
Bicep crashes and the largest detection bug of the run), plus this
worker's own perf / fuzz / coverage measurements.

**Date:** 2026-10-13. **Branch:** `mission/top-tier-validation`, HEAD
`2fbe9551fed140fff8ae4c1de031149e913f6a27`. **Binary:**
`/tmp/aegis-item6b/aegis` (`aegis 1.0.0`). **Machine:** 2 vCPU (AMD EPYC
9D25, host 126-core), 7.7 GiB RAM, Linux 7.0.0-39-generic x86_64, Go
1.25.0 (module-cache toolchain), `GOMAXPROCS=2`.

**Why a separate file:** the sibling report already occupied the
`14_SCALE_RELIABILITY.md` path when this worker reached the reporting
step. Overwriting it would have destroyed the sibling's delivered work.
The parent should merge the two files.

**Shared-tree disclosure:** this run executed concurrently with five
sibling workers (including the sibling Item 6 worker). The binary under
test contains siblings' uncommitted changes in addition to Item 6's.
Perf numbers describe "the tree as it stood". Fixes in §1 are this
worker's own, each verified before/after at the CLI. Twice a concurrent
edit made a test binary compile from a mid-edit state (one transient
`TestItem6CacheCyclePoisoning` failure, passing on re-run; several
transient `go test -fuzz [build failed]` lines). The sharper cause:
**/tmp (tmpfs, 512 MiB) sat at 95%+** from siblings' binaries, and Go's
default build work dir lives in /tmp — compiles failed with `no space
left on device` until this run moved `GOCACHE`/`GOTMPDIR` to disk
(`~/scratch-item6b/`). Nothing here rests on a run that overlapped a
build failure; every number below was re-measured after the move.

## 1. Bugs found and fixed by this worker

### 1.1 Bicep: infinite loop on unparseable array element (fuzzer-found, CRITICAL)

Input (47 bytes, fuzzer corpus `63c8ae091bf56177`):
`var x =[[[[ ~[[[[[\n` — CLI scan hung >20 s (killed by timeout).
Cause: `parseArray` looped until `]` or EOF; a failed `parseExpr`
returns Unknown **without consuming input**, so `~` spun forever.
Fix: `parseArray` fails the array when an element parse makes no
progress (`internal/adapter/bicep/bicep.go`), plus `parseExprOK`
propagation (§1.3). Regression test `TestItem6bArrayNoProgressHang`
with a 10 s watchdog per input (a regression fails the test instead of
hanging CI). Verified: CLI returns instantly, exit 0.
(Note: the sibling report §4.8 attributes this guard to "a sibling
worker" — that sibling is this worker.)

### 1.2 Bicep: index-out-of-range panic on `[` at EOF (fuzzer-found, CRITICAL)

Input: `var A=A[` — panic `index out of range [8] with length 8` in
`parseNumber` (`bicep.go:667`), called from the `[n]` suffix path in
`parseIdentOrCall`. The whole scanner process died. Fix: bounds-check
at `parseNumber` entry (return `false`). An audit of every other
`p.src[p.pos]` indexing site in the file found all others guarded
(`peek()`, loop conditions, or a preceding EOF check); `parseStringVal`
can overshoot `pos` by ≤3 past EOF on unterminated `'''`, which is
safe (all later accesses are guarded). Regression test
`TestItem6bNumberAtEOF`.

### 1.3 Bicep: failed expressions degraded to Unknown with no diagnostic

Demonstrated: `var open = [~]` feeding
`allowBlobPublicAccess: open` suppressed `AEGIS-AZR-001` (which needs
a known bool) with **zero diagnostics** — the conservative rule
`AEGIS-AZURE-028` still fired, so the finding class was not wholly
lost, but the precise rule vanished silently. (This is the "residual
observation" in sibling report §4.8 — now fixed, not residual.)
Fix: `parseExprOK()` distinguishes syntax failure (`ok=false`) from
legitimate Unknown (undeclared identifier, forward reference,
unsupported function — all still silent, correctly). `parseTernary`
branches, `parseArray` elements, and `parseCall` arguments propagate
`ok=false`; `parseVar`, `parseParam` (default), and `parseObject`
(property values) emit `… failed to parse; treated as unknown`
warnings. Regression tests: `TestItem6bFailedExprWarns`,
`TestItem6bFailedPropertyWarns`, and `TestItem6bForwardRefDoesNotWarn`
(forward refs must not warn).

### 1.4 Dockerfile: NUL bytes silently suppressed a finding

`USER \x00root` tokenized to user `"\x00root"` ≠ `"root"`, so
`AEGIS-DOCKER-002` (run-as-root) vanished: 6 findings vs 7 on the
clean file, **no diagnostic**. Fix: `Parse` strips NUL bytes and emits
one `dockerfile: file contains null bytes; stripped` warning; the
finding survives (7/7 + warning). Regression test
`TestItem6bNullBytesStrippedWithWarning`. Invalid UTF-8 in Dockerfiles
was verified harmless (findings preserved) and is left tolerated.

### 1.5 Compose: non-mapping service silently dropped

`services: {web: justastring}` dropped `web` with no diagnostic.
Fix: warning `compose: service web is not a mapping; skipped`; valid
sibling services still parse. Regression test
`TestItem6bNonMappingServiceWarns`.

### 1.6 Module expansion: scan-boundary escape + spurious warnings

`ExpandModules` expanded **every** discovered module's calls against
the **scan root**. A nested module's `source = "../secret"` therefore
resolved to `<parent-of-target>/secret`, and scanning `target/`
**ingested resources from a sibling directory the user never asked to
scan** (reproduced: `target/sub/m` calling `../secret` produced
`aws_s3_bucket.module.s.outside` findings from outside the target).
Every nested call that did not happen to resolve also produced a
spurious `cannot read directory` warning naming the wrong path (61
warnings on a 61-deep chain probe).
Fix (`internal/semantics/semantics.go`): only modules located directly
in the scan root seed expansion; nested calls expand via recursion
from the root call, which already passes each child's own directory as
the base. Post-fix: escape probe yields only the in-target
`module.m.in_m`, the warning names the correct path
(`target/sub/secret`), the deep-chain probe goes 61 warnings → 1
correct `exceeds max depth 2` diagnostic, and the cycle probe goes
3 diags → 1 (the cycle diagnostic). Existing semantics tests pass
unchanged (they only pass root modules). Documented limit: an
independent stack in a subdirectory (no root `.tf` calling into it)
has its module calls left unexpanded — its resources are still scanned
as files, but without module-input binding; scan the stack directory
itself to expand its modules. Root-level relative sources (e.g. the
root module calling `../shared`) are still honored: they are part of
the scanned stack by definition.
Regression tests: `TestItem6bNestedModuleSourceNotResolvedAgainstRoot`,
`TestItem6bNestedChainExpandsWithoutSpuriousWarnings`.

### 1.7 Terraform: JSON-style (`:`) object keys silently became Unknown

The largest detection bug found in this run. `jsonencode()` policy
documents written with JSON-style colon-separated quoted keys —
`{ "Effect": "Allow", "Action": "s3:*", "Resource": "*" }`, the form AWS
policy documents are pasted in as — evaluated to **Unknown with no
diagnostic**, so IAM policy rules (503/505/677) never fired. A
2,000-statement policy with a wildcard `Resource: "*"` at position
2,000 produced **0 findings**; the identical HCL-style policy
(`{ Effect = "Allow" ... }`) produced 3.
Root cause: quoted keys arrive as `*hclsyntax.ObjectConsKeyExpr`
wrapping a `TemplateExpr`; `hcl.ExprAsKeyword` returns `""` for those,
and neither `staticKeyString` nor `staticObjectKey` unwrapped them —
`staticExpr` has no `ObjectConsKeyExpr` case, so the whole object was
not static. (Raw HCL parses colon syntax cleanly; this was purely the
adapter's evaluator.)
Fix: both helpers unwrap `ObjectConsKeyExpr` and evaluate the wrapped
expression. Post-fix: colon-style 1-statement → 3 findings; colon-style
2,000-statement with wildcard last → 3 findings; all-scoped 2,000 →
1 finding (677). The fix covers `jsonencode()`, plain object
attributes, and `merge()` (they share the helpers). Regression tests:
`TestItem6bColonStyleJsonencodePolicy`,
`TestItem6bColonStylePlainObject`.

## 2. Performance — this worker's measurements (absolute numbers)

Methodology: deterministic generator (seed 20261013,
`docs/audit/raw/item6b/gen_perf.py`), 7 runs per corpus,
`aegis scan <dir> --format=json`, stdout piped and fully consumed,
peak RSS via fork/exec + `os.wait4()` `ru_maxrss`
(`docs/audit/raw/item6b/perf_run.py`). No Aegis-level cache exists, so
"cold" = first exec of the freshly built binary with warm OS page
cache (`drop_caches` denied). p50/p95/p99 are nearest-rank over 7
runs (p99 == max at n=7).

Corpora: `small` (10 files), `medium` (200), `large` (2,000, 7.9 MiB)
— mixed-provider mix per 10 files: 6 Terraform (S3 incl.
public-access block + encryption, SG world-open, Azure storage, GCP
bucket), 1 K8s Pod (privileged + hostNetwork), 1 CloudFormation S3
bucket, 1 ARM storage account, 1 of (Bicep storage / Dockerfile
`USER root` / Pulumi S3 in its own dir as `Pulumi.yaml`);
`modules` (91 files: root + 30 modules × 3 levels);
`deep-policy` (2 files: 40-level nested tags + one `jsonencode()` IAM
policy, 2,000 statements).

| Corpus | Files | Resources | Findings | min | **p50** | **p95** | max | Run 1 ("cold") | Peak RSS p50 | Peak RSS max |
|---|---|---|---|---|---|---|---|---|---|---|
| small | 10 | 13 | 116 | 29.6 ms | **37.9 ms** | 66.9 ms | 66.9 ms | 30.7 ms | 17.2 MiB | 17.7 MiB |
| medium | 200 | 292 | 1,952 | 127.0 ms | **303.9 ms** | 322.8 ms | 322.8 ms | 321.6 ms | 31.3 MiB | 34.3 MiB |
| large | 2,000 | 2,869 | 18,990 | 3,839.6 ms | **4,389.0 ms** | 6,345.9 ms | 6,345.9 ms | 6,104.1 ms | 174.4 MiB | 193.5 MiB |
| modules | 91 | 90 | 452 | 180.6 ms | **223.8 ms** | 376.5 ms | 376.5 ms | 298.0 ms | 21.4 MiB | 23.5 MiB |
| deep-policy | 2 | 2 | 7 | 505.1 ms | **622.0 ms** | 717.8 ms | 717.8 ms | 416.3 ms* | 35.4 MiB | 39.7 MiB |

\* deep-policy's first series (pre-§1.7-fix) measured p50 402.7 ms
with 6 findings; the post-fix series is 622.0 ms with 7 findings —
the fix costs ~200 ms on this 2-file corpus because the 2,000-statement
policy is now actually evaluated instead of dropped. That is
detection, not regression. (Sibling report §2.3 independently reports
the same pattern — +1 finding, +~1.1 s constant — for the
lenient-recovery fix on their corpus; the two fixes are different
mechanisms landing on the same rule, `AEGIS-AWS-677`.)

Throughput at p50: small 264 files/s, 343 resources/s; medium 658
files/s, 961 resources/s; large 456 files/s, 654 resources/s;
modules 407 files/s, 402 resources/s; deep-policy 3.2 files/s
(policy-eval dominated).

**Scaling exponents** (log-log, wall time): 10→200 files 0.69
(startup-dominated), 200→2,000 files **1.16**, 10→2,000 files 0.90;
by resources 292→2,869: **1.17**. Consistent with
`SCALING_RESOLUTION.md` ≈1.25 on dense workloads (this corpus is
sparser than that report's adversarial reference-dense workload).
No quadratic blowup observed.

**Cold/warm:** run 1 sits inside the warm distribution at every scale
(small run 1 was *faster* than p50). True cold-cache numbers were not
measured (`drop_caches` denied).

**Per-case extremes (adversarial probes, single files):**

| Case | Wall | Note |
|---|---|---|
| TF 50k-deep function nesting (`concat(`×50k) | 6.6 s | Parses; no cap hit (brace depth, not call depth) |
| TF 1M `[` (unbalanced) | 7.4 s | Bounded by lenient-repair byte budget; 1 error diag |
| TF 5 MiB string in `bucket` | ~1–5 s | Findings output 8 KiB (value not embedded) |
| ARM 5 MiB resource **name** | 6–17 s | §4, observation O1: ~100 MB findings output |
| Dockerfile 200k lines | 3.4 s | Linear |
| K8s 10k documents | 2.6 s | Linear |
| Bicep 1M `[` nesting | <15 s | Tolerated, no crash (Go stack growth) |
| Bicep 100k `[` nesting | 0.53–0.87 s | Tolerated |

## 3. Reliability (this worker)

- **Adversarial probes: 72 cases (58 + 14), 0 crashes, 0 hangs**
  post-fix (one subprocess per case, 30 s timeout; cases: deep
  nesting 5k–1M, huge strings 5 MiB, null bytes, invalid UTF-8,
  truncated input, alias cycles, billion-laughs expansion, cyclic /
  self / deep module references, unknown kinds/types, non-mapping
  services).
- **Determinism: 5/5 runs byte-identical** (sha256 `327cd3be…aa2db9`
  on `medium`, full JSON output).
- **Concurrency: 8 parallel CLI scans of `medium`, all byte-identical,
  all exit 0, empty stderr** (1,952 findings, 292 resources each).
- **`go test -race`: clean** on `internal/semantics`,
  `internal/discovery`, `internal/adapter/{terraform,bicep,compose,dockerfile}`,
  and `cmd/aegis` (covers `parseFilesConcurrent`).
- **Completeness accounting holds** on every probe: every discovered
  file lands in exactly one of parsed/skipped/failed with a reason,
  and every skip/failure carries a diagnostic naming the file.

## 4. Parser safety — fuzz + coverage per parser (this worker)

Fuzzing is coverage-guided (Go fuzzer, new-corpus-entries = new edges
found), 30–45 s per parser. Coverage below is the unit suite **plus**
fuzz-corpus replay (`go test -coverprofile`), i.e. the paths the
corpus actually executes — not an execution count.

| Parser | Fuzz execs (this run) | New interesting inputs | Crashes/hangs | Package stmt coverage |
|---|---|---|---|---|
| Terraform HCL (`FuzzParseModule`) | 85,402 | 73 (total corpus 82) | 0 | 79.7% |
| TF plan JSON | 542,006 | 163 (total 169) | 0 | 96.8% |
| CloudFormation | 50,738 | 67 (total 73) | 0 | 62.1% |
| ARM | 124,303 | 35 (total 176) | 0 | 54.2% |
| Bicep | 700,643 | 184 (total 212) | **2 found, both fixed** (§1.1, §1.2) | 73.4% |
| Pulumi YAML | 46,321 | 137 (total 143) | 0 | 87.0% |
| Dockerfile | 33,695 | 38 (total 102) | 0 | 66.5% |
| Compose | 80,352 | 215 (total 221) | 0 | 95.9% |
| K8s manifests | 51,798 | 142 (total 148) | 0 | 73.4% |
| **Total** | **≈1.85 M** | — | **2 (fixed)** | — |

Coverage gaps (functions <50%, from `go tool cover -func`):
ARM 54.2% is the lowest package figure — 2 funcs at 0%
(`arm.go:437,556`), expression-func coverage 28–41% in places;
CFN `props.go` has 9 funcs at 0% (rare-type converters),
`intrinsics.go` 3 at 0%; Dockerfile 5 funcs at 0%; the rest are
mostly trivial `Name()`/`Handles()` helpers at 0%. This is a residual
gap, not a safety claim — recorded as follow-up F2 in §6.
(Sibling report §5 measured unit+seed coverage with slightly
different totals — e.g. ARM `callFunc` 28.6% — consistent with this
worker's numbers; the two campaigns agree on where the gaps are.)

**Silent-suppression audit (per parser, post-fix):** every parser was
checked with a vulnerable resource + a hostile construct. All
0-findings cases in the final battery have either a diagnostic or are
legitimately empty/resource-less inputs. The four silent-suppression
bugs found by this worker (§1.3–§1.5, §1.7) are fixed and
regression-tested. Unknown-kind K8s documents become `k8s_<Kind>`
resources (no rules apply — by design, not a drop).

## 5. Observations not fixed (with rationale) and additional limits

**O1 — Finding-output amplification (not fixed).** A 5 MiB resource
*name* (ARM) yields ~100 MB of findings output (19 findings × the full
name embedded per finding) and 6–17 s dominated by serialization, not
parsing (a 5 MiB *tag* value on the same resource scans in 0.5 s).
Inherent to embedding full resource identifiers in every finding;
changing finding output shape is out of scope for a reliability item
and would ripple into every consumer. Recorded as a known
amplification, not a crash or suppression.

**O2 — Bicep `${...}` interpolation failures** still degrade to
`unknown()` without a diagnostic (`interpolate` uses a separate
mini-translator, not `parseExprOK`). Same Unknown semantics as other
adapters; a property fed solely by a malformed interpolation can miss
precise rules (conservative rules still fire). Left as a limit.

**O3 — Bicep invalid UTF-8 / NUL bytes** are tolerated with no
diagnostic; findings verified preserved (20/20 vs clean). Left as-is.

**O4 — TF pathological inputs are slow but bounded:** 1M `[` → 7.4 s
(lenient-repair budget), 50k-deep `concat(` nesting → 6.6 s. No cap
proposed: both terminate with diagnostics.

**O5 — Environment:** /tmp exhaustion (95%+, siblings' binaries)
caused transient Go build failures (`no space left on device`) and one
transient test failure during this run. Not an Aegis defect; noted so
a future run does not misread it as flakiness.

Additional limits beyond sibling report §7 (which this worker
endorses): module-expansion seeding — only root-dir modules seed
expansion; subdir stacks' calls expand only when the stack dir is the
scan target (§1.6). Pulumi routing — adapter only `Handles` exact
`Pulumi.yaml`/`Pulumi.yml` basenames; other names route to manifests
(this also affected the sibling report's corpus yield — see its §1
caveat, same cause).

## 6. Follow-ups (not done here)

- **F1:** Re-measure the `deep-policy` timing delta post-§1.7 on a
  quieter machine (622 ms vs 403 ms pre-fix on a loaded box — the
  delta is detection work, but the box was contended).
- **F2:** ARM expression-function coverage (54.2% package): add unit
  tests for the string/date/cidr function tail and the CFN `props.go`
  rare-type converters at 0%.
- **F3:** Consider a finding-output size guard for pathological
  resource names (O1) if 100 MB outputs are unacceptable downstream.
- **F4:** Bicep `${...}` interpolation failure diagnostics (O2).

## 7. Files changed by this worker

Source fixes:

- `internal/adapter/bicep/bicep.go` — parseArray progress guard;
  `parseExprOK` + propagation (ternary/array/call); failed-expression
  warnings (var/param/property); `parseNumber` EOF bounds-check.
- `internal/adapter/terraform/terraform.go` — unwrap
  `ObjectConsKeyExpr` in `staticKeyString` / `staticObjectKey`.
- `internal/adapter/dockerfile/dockerfile.go` — strip NUL bytes + warning.
- `internal/adapter/compose/compose.go` — warn on non-mapping service.
- `internal/semantics/semantics.go` — root-only module-expansion seeding.

Regression tests (new files, `item6b_*` to avoid colliding with the
sibling worker's `item6_*` files):

- `internal/adapter/bicep/item6b_test.go` (6 tests)
- `internal/adapter/terraform/item6b_test.go` (2 tests)
- `internal/adapter/dockerfile/item6b_test.go` (2 tests)
- `internal/adapter/compose/item6b_test.go` (1 test)
- `internal/semantics/item6b_test.go` (2 tests)

## 8. Verification (this worker)

- `go test ./internal/... ./cmd/... -count=1` — **all packages pass**.
- `go test -race` — clean on semantics, discovery, terraform, bicep,
  compose, dockerfile, `cmd/aegis`.
- Fuzz: ≈1.85 M execs across 9 parser targets, 0 crashes/hangs after
  fixes (2 Bicep bugs found and fixed during the run).
- Adversarial CLI probes: 72 cases, 0 crashes/hangs post-fix.
- Determinism 5/5 byte-identical; concurrency 8/8 byte-identical.

## 9. How to reproduce

```sh
export PATH=$HOME/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.25.0.linux-amd64/bin:$PATH
export GOFLAGS=-mod=mod GOPROXY=off GOCACHE=$HOME/scratch-item6b/gocache GOTMPDIR=$HOME/scratch-item6b/gotmp
go build -o /tmp/aegis-item6b/aegis ./cmd/aegis
go test ./internal/adapter/bicep/ -run '^$' -fuzz=FuzzItem6Parse -fuzztime=45s
go test ./internal/... ./cmd/... -count=1
python3 docs/audit/raw/item6b/gen_perf.py   # corpora -> ~/scratch-item6b/perf/ (regenerable)
python3 docs/audit/raw/item6b/perf_run.py ~/scratch-item6b/perf/large 7 large
```
