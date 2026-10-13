#!/usr/bin/env python3
"""Write RUNLOG.md from the accuracy + timing artifacts already on disk."""
import json, os, subprocess, statistics

OUT = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval/scanner-output/trivy")
FINAL_EVAL = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval")

v = subprocess.run([os.path.expanduser("~/workspace/bin/trivy"), "--version"],
                   capture_output=True, text=True).stdout.strip()
lines = [f"    {l}" for l in v.splitlines()]
version_block = "\n".join(lines)

exitcodes = json.load(open(os.path.join(OUT, "EXITCODES.json")))
failures = json.load(open(os.path.join(OUT, "FAILURES.json")))
meta = json.load(open(os.path.join(OUT, "meta.json")))
timing = json.load(open(os.path.join(OUT, "TIMING.json")))
manifest = json.load(open(os.path.join(FINAL_EVAL, "corpus", "MANIFEST.json")))
fmts = {e["id"]: e["format"] for e in manifest}

n_ok = sum(1 for r in exitcodes.values() if r["status"] == "ok")
n_skip = sum(1 for r in exitcodes.values() if r["status"] == "native_skip")
n_fail = sum(1 for r in exitcodes.values() if r["status"] == "failed")
skip_ids = sorted(pid for pid, r in exitcodes.items() if r["status"] == "native_skip")
assert n_ok + n_skip + n_fail == 205 == len(exitcodes)

colds = [r["cold"] for r in timing.values()]
warms = [w for r in timing.values() for w in r["warm"]]
rsss = [r["peak_rss_kb"] for r in timing.values()]
cold_med = statistics.median(colds)
warm_med = statistics.median(warms)
rss_med = statistics.median(rsss)

fail_lines = []
if failures:
    for pid in sorted(failures):
        f = failures[pid]
        fail_lines.append(f"- **{pid}**: {f['reason']}")
        fail_lines.append(f"  stderr tail:\n```\n{f['stderr_tail']}\n```")
else:
    fail_lines.append("- none")

doc = f"""# Trivy 0.74.0 — final-eval blind sweep run log

## Scanner
{version_block}
- Binary: `~/workspace/bin/trivy`
- Check bundle cached 2026-10-12 (`~/.cache/trivy/policy/content`); pre-existing
  cache used with `--skip-check-update`, so no per-run downloads (timing deterministic).

## Invocation (identical for accuracy and timing)
```
~/workspace/bin/trivy config --skip-version-check --skip-check-update \\
    --format json --output <out>/<id>.json \\
    ~/workspace/aegis-engine/docs/audit/raw/final-eval/corpus/<id>
```
- `trivy config` in 0.74.0 does NOT accept `--scanners` or `--security-checks`
  (both rejected as unknown flags); its default mode is already misconfig-only.
- `--skip-version-check` suppresses the update notice; `--skip-check-update`
  uses the cached check bundle with no network refresh.
- Trivy exits 0 in misconfig mode even when findings exist (no `--exit-code` flag used).

## Timestamps
- Accuracy sweep start: {meta['start']}
- Accuracy sweep end: {meta['end']}
- Accuracy wall time: {meta['wall_s']} s (~{meta['wall_s']/205:.1f} s/project)
- Timing sweep: {len(timing)} projects x 5 runs, 300 s timeout each
- Timeout per scan: 300 s

## Accuracy results
- Scanned: {len(exitcodes)}/205 projects
- **OK: {n_ok}** — exit 0, valid JSON, counted misconfig findings recorded
- **Native skip: {n_skip}** — exit 0 with empty Results because trivy 0.74.0
  `config` has NO native scanner for the project's format. NOT failures, NOT
  retried, NOT counted as zero findings silently. All are `bicep` / `pulumi` /
  `compose` per the corpus MANIFEST.json:
  - {', '.join(skip_ids)}
- **Failed: {n_fail}**

## Failures
{chr(10).join(fail_lines)}

Failure policy: nonzero exit or timeout (>300 s) -> stderr saved to
`<id>.stderr.txt`, retried once, then recorded as failed in FAILURES.json and
EXITCODES.json. Failed scans are never counted as zero findings.

## Timing results (30 timing-subset ids, 5 runs each)
- Warm-up: one throwaway scan of an empty dir before timed runs, so run 1 =
  cold process with warm caches (NOT cold download).
- Median cold (run 1): {cold_med:.2f} s
- Median warm (runs 2-5 pooled): {warm_med:.2f} s
- Median peak RSS: {rss_med:,.0f} kB
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
"""
with open(os.path.join(OUT, "RUNLOG.md"), "w") as f:
    f.write(doc)
print(f"RUNLOG.md written: {n_ok} ok, {n_skip} native-skip, {n_fail} failed, "
      f"cold_med={cold_med:.2f}s warm_med={warm_med:.2f}s")
