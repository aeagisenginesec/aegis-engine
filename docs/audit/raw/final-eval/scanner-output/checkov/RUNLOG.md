# RUNLOG — Checkov 3.3.26 blind-corpus sweep

## Version

`~/workspace/.venv-checkov/bin/checkov --version` → verbatim stdout:

```
3.3.26
```

Version check passed before any scan was started; the accuracy script refuses to run on any other version.

Note: checkov's stderr carried an "Update available 3.3.26 -> 3.3.28" notice during the pre-sweep pilot runs. The scan ran pinned at **3.3.26** per the task requirement.

## Exact commands used

Accuracy sweep (205 projects, per project, `run_checkov_accuracy.py`):

```
/home/hatch/workspace/.venv-checkov/bin/checkov -d <corpus>/<id> -o json --quiet
```

- stdout saved verbatim to `<out>/<id>.json`; timeout **300 s** per project.
- DEFAULT framework auto-detection — no `--skip-framework` passed; the secrets framework is included by default (matches the prior round).
- On exit 2 / crash / timeout: record stderr tail, retry exactly once, then record as failed. No such event occurred (see Failures).

Timing sweep (30 ids from `timing-subset.json`, `run_checkov_timing.py` via `timing_harness.time_project`):

```python
time_project(cmd, cwd=None, runs=5, timeout=300)
# cmd = ["/home/hatch/workspace/.venv-checkov/bin/checkov", "-d", "<corpus>/<id>", "-o", "json", "--quiet"]
```

- 5 runs per id (run 1 = cold); results in `TIMING.json` as
  `{"<id>": {"cold": s, "warm": [s,s,s,s], "peak_rss_kb": N, "exit_codes": [...]}}`,
  plus `TIMING_META.json` with start/end timestamps.
- The timing sweep was run **after** the accuracy sweep completed (sequential), to avoid CPU contention distorting timings. The shared VM carries other concurrent scanner sweeps, so some warm timings drift upward — see Timing notes.

## Timestamps (UTC; log uses `%Y-%m-%dT%H:%M:%S%z`)

| Phase | Start | End | Wall time |
|---|---|---|---|
| Accuracy sweep (205/205) | 2026-10-13T00:03:24+0000 | 2026-10-13T01:01:57+0000 | 3512.9 s (58.5 min) |
| Timing sweep (30/30) | 2026-10-13T01:02:01+0000 | 2026-10-13T01:19:40+0000 | 1058.9 s (17.6 min) |
| **Total** | | | **4571.8 s (~76.2 min)** |

## Accuracy results

- Scanned OK: **205 / 205**. Failed: **0** (no `FAILURES.json` was written — nothing to record).
- Exit codes (`EXITCODES.json`): **162 × exit 1** (failed checks found), **43 × exit 0** (no failed checks / no engagement), **0 × exit 2**. No crashes, no timeouts; the retry-once path was never triggered.

### Output shapes (checkov 3.3.26)

- 169 ids: single engaged framework → bare dict with `check_type` and `summary`.
- 9 ids: two frameworks engaged → **list** of two per-framework dicts.
- 27 ids: no framework engaged → bare summary dict
  `{"passed","failed","skipped","parsing_errors","resource_count","checkov_version"}` (138 bytes), exit 0.

### Framework engagement across the corpus

| check_type | ids |
|---|---|
| terraform | 72 |
| secrets | 7 |
| cloudformation | 24 |
| arm | 15 |
| bicep | 13 |
| dockerfile | 32 |
| kubernetes | 24 |

Two-framework combos: c009 (cloudformation+secrets), k002/k008/k051 (dockerfile+secrets),
t007/t009 (terraform+secrets), k056 (kubernetes+terraform), k059/k065 (dockerfile+kubernetes).

### Per-format notes

- **Bicep**: 13 ids engaged (c041–c049, c051–c054). c043 and c053 engaged bicep with all checks passed (5 passed, 0 failed, exit 0); c049 engaged bicep but with 0 resources (0 passed, 0 failed); c041/c042/c044–c048/c051/c052/c054 produced bicep findings (exit 1). **c050 and c055** (each containing only `main.bicep`) silently engaged nothing — bare 138-byte summary, exit 0. A pilot re-run of c050 with an explicit `--framework bicep` also produced nothing (banner only). pycep is installed in the venv; the no-op is per-file behavior, cause not determined.
- **Pulumi**: c056–c070 (each a `Pulumi.yaml` dir) → bare summary, exit 0. Checkov 3.3.26 has **no Pulumi framework**; these projects are unscanned.
- **Docker Compose**: k041 and k043–k050 contain only `docker-compose.yml` → no framework engaged (bare summary, exit 0). Checkov 3.3.26 did not pick up standalone compose files in this corpus; k-dirs with a Dockerfile alongside compose engaged the dockerfile framework. No `docker_compose` check_type appeared in any output.
- **c012** (`vpc.yaml`) → bare summary, `resource_count: 0`, exit 0; no framework engaged.
- **Secrets**: engaged on 7 ids (c009, k002, k008, k042, k051, t007, t009); findings were recorded as failed checks (e.g. k042: 4 failed secret checks). Default scan set covers `.tf/.yml/.yaml/.json/.template/.bicep/.hcl` plus Dockerfiles; verified in pilot that `.py` files are **not** scanned (an AWS key planted in `app.py` produced zero findings).
- Small exit-0 outputs are not all no-ops: e.g. k003 is a dockerfile dict (43 passed, 0 failed, 270 B) and c014 a cloudformation dict (5 passed, 0 failed, 273 B). The 27 bare-summary ids above are the true no-engagement cases.

## Failures

None. 205 ok / 0 failed. No exit-2 runs, no crashes, no per-project timeouts.

## Timing results

- 30 / 30 ids timed (5 runs each), no timeouts; all per-run exit codes match each id's accuracy-sweep exit code (exit-0 ids returned five 0s, exit-1 ids five 1s).
- **Cold median: 6.4 s** (mean 7.2 s, min 5.4 s, max 12.4 s — k043).
- **Warm median: 6.3 s** (mean 7.0 s, min 5.1 s, max 15.3 s).
- Peak RSS: median 213452 KB (~208 MB). Caveat: `timing_harness.time_project` reports the cumulative `RUSAGE_CHILDREN` max across all runs in the process, so `peak_rss_kb` is the running maximum seen so far, not a per-project measurement.
- VM-contention note: warm timings drifted upward in the second half of the sweep (e.g. k007 warm runs of 11.6/12.2 s, k037, k043), consistent with other scanner sweeps sharing this 2-core VM during the run.

## Corpus

Read-only throughout — no corpus file was modified. All 205 project directories (t001–t070, c001–c070, k001–k065) verified present before the sweep.
