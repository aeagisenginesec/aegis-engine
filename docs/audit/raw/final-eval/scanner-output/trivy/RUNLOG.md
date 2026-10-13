# Trivy 0.74.0 — final-eval blind sweep run log

## Scanner
    Version: 0.74.0
    Check Bundle:
      Digest: sha256:1583562f8b90ed2a071b99f0e5ffff6b57e4ceb6ca3e4796577b4e6a339eb74c
      DownloadedAt: 2026-10-12 01:39:11.065696483 +0000 UTC
- Binary: `~/workspace/bin/trivy`
- Check bundle cached 2026-10-12 (`~/.cache/trivy/policy/content`); pre-existing
  cache used with `--skip-check-update`, so no per-run downloads (timing deterministic).

## Invocation (identical for accuracy and timing)
```
~/workspace/bin/trivy config --skip-version-check --skip-check-update \
    --format json --output <out>/<id>.json \
    ~/workspace/aegis-engine/docs/audit/raw/final-eval/corpus/<id>
```
- `trivy config` in 0.74.0 does NOT accept `--scanners` or `--security-checks`
  (both rejected as unknown flags); its default mode is already misconfig-only.
- `--skip-version-check` suppresses the update notice; `--skip-check-update`
  uses the cached check bundle with no network refresh.
- Trivy exits 0 in misconfig mode even when findings exist (no `--exit-code` flag used).

## Timestamps
- Accuracy sweep start: 2026-10-12 23:49:51 +0000
- Accuracy sweep end: 2026-10-13 00:17:46 +0000
- Accuracy wall time: 1674.9 s (~8.2 s/project)
- Timing sweep: 30 projects x 5 runs, 300 s timeout each
- Timeout per scan: 300 s

## Accuracy results
- Scanned: 205/205 projects
- **OK: 165** — exit 0, valid JSON, counted misconfig findings recorded
- **Native skip: 40** — exit 0 with empty Results because trivy 0.74.0
  `config` has NO native scanner for the project's format. NOT failures, NOT
  retried, NOT counted as zero findings silently. All are `bicep` / `pulumi` /
  `compose` per the corpus MANIFEST.json:
  - c041, c042, c043, c044, c045, c046, c047, c048, c049, c050, c051, c052, c053, c054, c055, c056, c057, c058, c059, c060, c061, c062, c063, c064, c065, c066, c067, c068, c069, c070, k041, k042, k043, k044, k045, k046, k047, k048, k049, k050
- **Failed: 0**

## Failures
- none

Failure policy: nonzero exit or timeout (>300 s) -> stderr saved to
`<id>.stderr.txt`, retried once, then recorded as failed in FAILURES.json and
EXITCODES.json. Failed scans are never counted as zero findings.

## Timing results (30 timing-subset ids, 5 runs each)
- Warm-up: one throwaway scan of an empty dir before timed runs, so run 1 =
  cold process with warm caches (NOT cold download).
- Median cold (run 1): 6.09 s
- Median warm (runs 2-5 pooled): 6.53 s
- Median peak RSS: 211,998 kB
- Full per-project records (cold, warm[4], peak_rss_kb, exit_codes): TIMING.json

## Artifacts in this directory
- `<id>.json` — per-project trivy JSON reports (accuracy sweep)
- `EXITCODES.json` — exit code + status + misconfig counts per project
- `FAILURES.json` — failed ids with stderr tails
- `TIMING.json` — per-project timing records for the 30-id subset
- `meta.json` — accuracy sweep start/end timestamps and wall time
- `timing-tmp/` — throwaway timing scan outputs (not analysis artifacts)
- `run_accuracy.py`, `run_timing.py`, `write_runlog.py` — sweep scripts

## Scripts
- Adapted from the verified `~/workspace/eval2-trivy/run_accuracy.py` /
  `run_timing.py` (paths updated; failure handling upgraded: retry-once,
  FAILURES.json, native-skip classification via MANIFEST.json format).
- Timing uses the shared harness
  `~/workspace/aegis-engine/docs/audit/raw/final-eval/timing_harness.py`
  (`time_project(runs=5, timeout=300)`; wall via perf_counter, peak RSS via
  getrusage RUSAGE_CHILDREN).

## Resume history (what actually happened)

- A resume task was created on the assumption that a prior worker had been
  killed by a daemon restart at 63/205. That assumption was WRONG.
- When the resume worker checked at 2026-10-13 00:01 UTC, the original nohup
  worker (`bash -c "python3 run_accuracy.py && python3 run_timing.py &&
  python3 write_runlog.py"`, launched 2026-10-12 ~23:49 UTC, pid 46862/46867)
  was alive and already at [92/205] in `sweep.log` — one continuous run.
- No parallel sweep was launched by the resume worker: a second
  `run_accuracy.py` would have collided with the live worker on
  `EXITCODES.json` (per-project atomic-replace flushes would clobber each
  other's records). Per-project `<id>.json` writes were idempotent by
  filename, but `EXITCODES.json` rebuilds were not safe to interleave.
- At check time, 75 per-project JSONs already existed on disk (c001-c070,
  k001, k002, k041, t001) and all parsed as valid Trivy 0.74.0 reports
  (SchemaVersion 2). The 32 reports without a top-level `Results` key
  (c041-c070, k041) are NOT corrupt: Trivy omits `Results` entirely when it
  is empty; all were exit 0 native skips (bicep/pulumi/compose per
  MANIFEST.json) — the same classification the sweep script itself uses
  (`data.get("Results") or []`).
- The live worker then completed the remaining 130 projects in the same
  continuous run: accuracy reached [205/205] at 00:18 UTC (total accuracy
  wall 1674.9 s, ~8.2 s/project), the timing sweep ran 30 ids x 5 runs
  (warm-up throwaway of an empty dir first), and `write_runlog.py` produced
  this RUNLOG.md. So: **no ids were separately redone by a second worker** —
  all 205 were scanned in one continuous pass; the already-present JSONs
  were rewritten in place by that same pass.
- Note on timing medians: median cold 6.09 s vs median warm 6.53 s — warm is
  not meaningfully faster here because the throwaway warm-up already warmed
  the caches before run 1; both reflect steady-state scan cost.
