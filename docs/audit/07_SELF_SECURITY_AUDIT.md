# Phase 8 — Self-Security Audit

**Date:** 2026-10-12
**Target:** `~/workspace/aegis-engine`, branch `fix/demo-defects-d1-d3`, HEAD `0c28621`
**Binary under test:** built from HEAD (`go build -o /tmp/aegis-p8 ./cmd/aegis/`)
**Scope:** HTTP API (`aegis serve`), all 9 adapter parsers, resource limits, determinism.
**Method:** black-box probing + Go native fuzzing (`go test -fuzz`) from a scratch copy of
the repo (`~/workspace/.p8scratch/`, since removed from the report path but retained for
repro). **Read-only on source: no code modified, nothing committed, no branch switch.**
(Note: `git status` shows the tracked `aegis` binary as modified — its mtime
2026-10-12 17:21 UTC predates this audit session; a prior phase rebuilt it. All
Phase 8 testing used a fresh `/tmp/aegis-p8` build from HEAD.)

## Executive summary

| Area | Verdict |
|---|---|
| HTTP API binding default | ✅ Loopback-only (`127.0.0.1:8734`), verified via `ss` |
| HTTP API malformed/oversized/concurrent input | ✅ Clean — correct codes, no crash, no stack-trace leak, no FD/thread leak |
| Fuzzing (9 parsers) | ⚠️ **1 crasher found (bicep, Medium)**; 8 parsers clean for their time budgets |
| Adversarial inputs (20 cases) | ✅ No hangs, no crashes; explicit diagnostics (2 minor gaps, Low) |
| Resource limits | ⚠️ `--max-file-size` bounds reads but **over-cap files are silently dropped** (Low); terraform adapter has its own hard 10 MiB gate (explicit diagnostic) |
| `--timeout` | ✅ Behaves: CLI aborts the wait at the deadline and exits; scan does not continue in CLI use (process exits) |
| Determinism | ✅ 3/3 identical SHA-256 over adversarial corpus |

**What a crash-free fuzz run does and doesn't establish:** the clean runs establish that
~2.07M mutated inputs across 9 parsers produced no panic, hang, or OOM *within the
fuzzer's coverage* in 1–3 minutes per target. They do **not** prove absence of bugs:
fuzzing is a sampling method, time-boxed, single-threaded-mutation, and seed-relative.
The bicep crasher was found in <2 s — a reminder that absence of crashes in the other
parsers is weak evidence, not a guarantee. The quality gate's "parser-safety 15/15"
claim (see §6) covers only the terraform adapter with 15 hand-written cases, so it
cannot be read as whole-product parser safety.

## Findings (severity-rated)

| # | Severity | Title | Detail |
|---|---|---|---|
| F-1 | **Medium** | Bicep parser panics on unterminated `'''` string (`resource A0'''0`) | `parseStringVal` does a blind `p.pos += 3` after scanning for a closing `'''` that never comes; `p.pos` overshoots `len(src)` and the next `parseKeyword` slices `p.src[18:18]` on a 15-byte buffer → panic. Repro in `docs/audit/raw/phase8/crashes/`. **Contained in production** — CLI and `serve` wrap `Parse` in `safeParse` panic recovery (verified live: HTTP 200 + error diagnostic, no stack trace, server stays up). Any future caller that skips the recover wrapper would crash. |
| F-2 | Low | Unterminated bicep multiline string silently accepted in property position | `name: '''unterminated` (no closing delimiter) parses with **zero diagnostics** and emits the resource — malformed input is silently absorbed instead of producing an explicit diagnostic. Same root-cause family as F-1. |
| F-3 | Low | Files over `--max-file-size` are silently excluded from the scan | A 51 MB file in a 501-file directory produced `files_discovered: 500` with **no skip record, no warning, no diagnostic** — the file simply vanishes from `scan_completeness`. For a security scanner this is a silent coverage gap. (The cap itself works: the file is never read into memory.) |
| F-4 | Low | `aegis serve --addr 0.0.0.0:...` binds all interfaces with no warning | Explicit user choice, so expected — but the log line is a plain `listening on 0.0.0.0:18735` with no security warning, and the API has no auth/TLS. A loud warning would be cheap. |
| F-5 | Low | Panic value echoed into API diagnostic | `serve` returns `adapter bicep panicked: runtime error: slice bounds out of range [:18] with length 15` to the client. No stack trace (good), but internal panic text is disclosed. Trivial. |
| F-6 | Low | `--max-file-size` override doesn't affect the terraform adapter's own 10 MiB gate | Discovery honored `--max-file-size=60000000` and admitted a 51 MB file, but the terraform adapter refused it with its own hardcoded `file exceeds 10 MiB limit` — explicit diagnostic (good), but the flag's documented effect ("per-file size cap") is misleading for terraform files. |

---

## 1. HTTP API audit (`aegis serve`)

Server started as `/tmp/aegis-p8 serve` (default args). All tests against `127.0.0.1:8734`.

### 1.1 Binding

| Test | Result |
|---|---|
| Default bind | ✅ `ss -tlnp` shows `127.0.0.1:8734` only — **loopback-only confirmed**, matches `--help` |
| `--addr 0.0.0.0:18735` | Binds `*:18735`; log line `aegis serve: listening on 0.0.0.0:18735` — **no warning** (F-4). Instance killed immediately after verification. |
| Port conflict (second instance) | Clean failure: `listen tcp 127.0.0.1:8734: bind: address already in use`, exit 1 |

### 1.2 Request handling

| Test | Response |
|---|---|
| `GET /v1/health` | 200 `{"status":"ok","version":"1.0.0"}` |
| `POST /v1/health` | 405 |
| `GET /v1/scan` | 405 |
| `GET /nope` | 404 |
| `GET /debug/pprof/` | 404 — **pprof not exposed** ✅ |
| `POST /v1/scan` malformed JSON (`this is not json{`) | 400 `{"error":"invalid JSON body"}` |
| `POST /v1/scan` empty body | 400 `{"error":"invalid JSON body"}` |
| `POST /v1/scan` `{"files":[]}` | 200, empty result |
| `POST /v1/scan` unknown ruleset `"bogus"` | 400 `{"error":"unknown ruleset"}` |
| `POST /v1/scan` wrong Content-Type (`text/plain`, valid JSON body) | 200 — Content-Type ignored, body parsed anyway (documented behavior choice, not a finding) |
| 10 MB / 100 MB **invalid**-JSON bodies | 400 (syntax error precedes the size check — decoder fails on first byte) |
| 33 MB **valid**-JSON body | **413** `{"error":"request body exceeds 32 MiB"}` in 0.28 s ✅ |
| 33 MiB via `Transfer-Encoding: chunked` (no Content-Length) | **413** ✅ — cap enforced on streamed bodies too |
| 50 parallel `POST /v1/scan` | 50/50 → 200, no errors |
| Slow-loris (headers complete, partial body held 12 s, then completed) | Connection held; server-side 60 s `TimeoutHandler` bounds it; after the storm: threads 6→6, FDs 7→6, RSS back to ~16 MB — **no leak** ✅ |
| Panic-inducing input (`resource A0'''0` bicep via API) | 200 + `diagnostics[0].level=error`, message `parse failed for main.bicep: adapter bicep panicked: ...` — **no stack trace leaked**, server alive (F-5 notes the panic text itself is echoed) |

No `ReadTimeout` is set (only `ReadHeaderTimeout: 10s`), so a client can trickle a
request body — but `http.TimeoutHandler(..., 60s)` caps the handler lifetime, and the
connection is then closed. Slow-loris is therefore bounded at ~60 s per connection;
no unbounded goroutine accumulation was observed.

### 1.3 What the API does well

- `http.MaxBytesReader` (32 MiB) + `maxScanFiles` (1000) + 60 s timeout: all three
bounds verified working.
- Panic recovery in the parse path (`safeParse`/`safeParseModule`) holds under the
live server — the one parser panic found by fuzzing degrades to a diagnostic.
- No stack traces, no pprof, no version banner beyond the health JSON.

---

## 2. Parser fuzzing

Harness: `go test -fuzz` targets calling each adapter's `Parse` (terraform via
`ParseModule`) **without** a recover wrapper, so any parser panic surfaces as a
fuzzer failure. Run from a scratch copy of the repo (source untouched).
New parsers: 3 min each; existing parsers: 1 min each.

| Parser | Time | Execs | Result |
|---|---|---|---|
| cloudformation (YAML) | 3 m | 143,745 | ✅ PASS, no crashers |
| cloudformation (JSON) | 3 m | 143,034 | ✅ PASS, no crashers |
| arm | 3 m | 838,346 | ✅ PASS, no crashers |
| bicep | 3 m | — | ❌ **CRASHER in 1.8 s** (F-1) |
| pulumi | 3 m | 103,300 | ✅ PASS, no crashers |
| terraform | 1 m | 98,388 | ✅ PASS, no crashers |
| planjson | 1 m | 344,633 | ✅ PASS, no crashers |
| dockerfile | 1 m | 350,371 | ✅ PASS, no crashers |
| compose | 1 m | 108,864 | ✅ PASS, no crashers |
| manifests | 1 m | 39,721 | ✅ PASS, no crashers |

~2.07M total execs. No hangs (>30 s single input) and no excessive-memory
failures in any target.
Note: brief `0 execs/sec` lulls were observed mid-run (some mutants are slow to
parse), but every target completed its `-fuzztime` window — no stalls.

**Environment incident (not a product finding):** the first planjson/dockerfile/
compose/manifests runs died with `SIGBUS` inside Go's own fuzz shared-memory code
and a linker `no space left on device` — `/tmp` (512 MB tmpfs) was 100% full from
other phases' artifacts. Reruns with `TMPDIR`/`GOTMPDIR` on a roomy filesystem
passed. The SIGBUS is Go-runtime-vs-full-tmpfs, not an Aegis defect.

### Crashers

**F-1 (Medium): bicep `parseKeyword` slice-out-of-range** — repro + README in
`docs/audit/raw/phase8/crashes/bicep-parseKeyword-slice-oob.{input,README}`.
15-byte input `resource A0'''0`; panic `slice bounds out of range [:18] with
length 15` at `bicep.go:201` (`parseKeyword`), called from `parseResource`
(`bicep.go:373`). Root cause: `parseStringVal`'s blind `p.pos += 3` after an
unterminated `'''` multiline string (bicep.go ~line 258) overshoots the buffer;
the subsequent `p.src[start:p.pos]` panics. Production impact contained via
`safeParse` recovery (verified live over HTTP).

---

## 3. Adversarial inputs (deterministic)

Each file scanned alone via CLI with a 30 s hang watchdog. **Zero hangs, zero
crashes** across all 20 inputs.

| Input | Routed to | Outcome |
|---|---|---|
| 10k-deep YAML (CFN-marked, 2.3 MB, 1500 lvl) | cloudformation | ✅ parsed, 1 resource |
| 10k-deep JSON (CFN-marked) | cloudformation | ✅ explicit error: `yaml: exceeded max depth of 10000` |
| 10k-deep JSON (ARM-marked) | arm | ✅ explicit error: `invalid character '{' exceeded max depth` (Go json 10k cap) |
| 10k-deep `.plan.json` | planjson | ✅ explicit error diagnostic |
| 10k-deep HCL object nesting (2000 lvl) | terraform | ✅ explicit error: `nesting depth exceeds 50 levels` |
| 5000-deep `[concat(...)]` (ARM-marked) | arm | ✅ parsed, no hang (unmapped-type warning) |
| 5000-deep bicep array | bicep | ✅ parsed, no hang |
| 1500-deep Pulumi YAML | pulumi | ✅ parsed, 1 resource |
| Billion-laughs YAML anchors (CFN-marked) | cloudformation | ✅ parsed, 1 resource — **no expansion blowup** (adapter decodes to `yaml.Node`; aliases stay references) |
| YAML anchors/aliases (sane) | cloudformation | ✅ parsed |
| Cyclic `!Ref` (A↔B) | cloudformation | ✅ parsed, 2 resources, exit 1 (findings) — no infinite loop |
| Cyclic `depends_on` (a↔b) | terraform | ✅ exit 1 (findings) — no hang |
| Null bytes (`.tf`) | terraform | ✅ explicit error: `file contains null bytes; not valid UTF-8 HCL` |
| Null bytes (`.yaml`/`.json`) | manifests | ✅ explicit YAML error diagnostic |
| Invalid UTF-8 (`.tf`) | terraform | ✅ parsed with explicit handling |
| Invalid UTF-8 (`.yaml`) | manifests | ✅ error diagnostic: `yaml: invalid leading UTF-8 octet` |
| 200k repeated HCL blocks (11 MB) | — (over size cap) | ✅ excluded by discovery, no hang |
| 10 MB single `.tf` / 10 MB `.yaml` | — (over size cap) | ✅ excluded by discovery, no hang |
| 1M-line Dockerfile (12 MB) | — (over size cap) | ✅ excluded by discovery, no hang |
| Unterminated bicep `'''` (property) | bicep | ⚠️ parsed, 1 resource, **zero diagnostics** (F-2) |

Two gaps, both Low: F-2 (silent acceptance) and F-3 (silent size exclusion, §4).

---

## 4. Resource limits

### `--max-file-size`

- Default cap: 10 MiB (`internal/discovery`, `MaxFileBytes = 10 << 20`; `--help`
documents `default 10485760`). Verified: 100 MB YAML, 10.48 MB TF, 51 MB TF —
all **excluded before reading** (`files_discovered` doesn't even count them).
- Memory: 500-file scan peaked at ~36 MB RSS; the 51 MB file was never mapped.
The cap genuinely bounds read memory. ✅
- **Gap (F-3, Low):** excluded files leave **no trace** — no `skipped` entry, no
warning, no diagnostic. `scan_completeness` reported 500/500 for a 501-file
directory. Silent coverage gap.
- **Inconsistency (F-6, Low):** `--max-file-size=60000000` admitted the 51 MB
file at discovery, but the terraform adapter refused it with its own hardcoded
`file exceeds 10 MiB limit` — explicit diagnostic (good), but the flag's
documented meaning ("per-file size cap") doesn't hold for terraform files.

### `--timeout`

- 30k-file scan takes ~9.2 s without the flag. With `--timeout=3`: CLI exited at
**3.1 s, exit 2**, no partial output, no hang.
- The known limitation is confirmed as described: the timeout bounds how long
the CLI *waits* (`scanWithTimeout` + `time.After`); the scan goroutine is not
cooperatively cancelled. In CLI use this is moot — the process exits, taking the
goroutine with it (no leak observed). It would matter only for in-process
library use, which is not a shipped surface today.

---

## 5. Determinism

Adversarial corpus (11 files: CFN deep/laughs/anchors, ARM deep-expr, bicep
deep + unterminated, Pulumi deep, planjson deep, cyclic Ref, null bytes, bad
UTF-8) scanned 3× via `aegis scan --format=json`; SHA-256 of full output:

```
c3ac320c3ae2f16ef8e31f058b0b6991d293137175ce3f34092311b5ea88f3cd
c3ac320c3ae2f16ef8e31f058b0b6991d293137175ce3f34092311b5ea88f3cd
c3ac320c3ae2f16ef8e31f058b0b6991d293137175ce3f34092311b5ea88f3cd
```

✅ **3/3 identical.**

---

## 6. Note on the "parser-safety 15/15" quality gate (independent verification)

The gate (`internal/qualitygate/parser.go`) was read, not trusted. What it
actually is: **15 hand-written malformed inputs run through the terraform
adapter only**, where "explicit" = returns an error or any diagnostic. It does
not cover the other 8 adapters, uses no mutation/fuzzing, and would not catch
F-1 (a bicep panic — a different adapter entirely; note a panic in a probed
adapter would crash the gate itself rather than fail gracefully). The claim is
accurate for what it measures (terraform malformed-input explicitness) and
should not be read as whole-product parser safety.

---

## 7. Residual risks / recommended follow-ups

1. **Fix F-1**: guard the `p.pos += 3` in bicep `parseStringVal` (only advance
past a delimiter that was actually found); consider a defensive
`p.pos > len(p.src)` clamp in the parser hot path. Add the 15-byte input as a
regression test.
2. **F-3**: emit a `skipped`/warning entry (or diagnostic) for size-excluded
files so `scan_completeness` is honest.
3. **F-4**: log a warning when `serve --addr` binds a non-loopback address.
4. Extend the parser-safety gate (or a fuzz corpus) to all 9 adapters; the
bicep crasher proves the terraform-only gate has a blind spot. The fuzz
harness used here (`Parse` per adapter, no recover) is a reusable template.
5. Longer fuzz budgets (the 1–3 min windows here are a smoke test, not a
campaign) and structure-aware seeds per adapter.

## Artifacts

- This report: `docs/audit/07_SELF_SECURITY_AUDIT.md`
- Crash repro: `docs/audit/raw/phase8/crashes/bicep-parseKeyword-slice-oob.input`
  (+ `.README` with stack, root cause, repro)
- Scratch (fuzz harness, corpora, logs): `~/workspace/.p8scratch/` (outside the
repo; safe to delete after review)
