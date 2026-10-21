#!/usr/bin/env python3
"""Timing sweep: trivy config 0.74.0 over the 30 timing-subset projects.

- One throwaway warm-up scan of an empty dir first, so timed run 1 = cold
  process (caches already warm), NOT cold download.
- Per project: timing_harness.time_project(runs=5, timeout=300)
  -> {"<id>": {"cold": s, "warm": [...], "peak_rss_kb": N, "exit_codes": [...]}}
- Timing throwaway scan outputs go to <out>/timing-tmp/ so accuracy artifacts
  (<id>.json) stay pristine.
- Writes <out>/TIMING.json.
"""
import json, os, subprocess, sys

OUT = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval/scanner-output/trivy")
CORPUS = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval/corpus")
FINAL_EVAL = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval")
TRIVY = os.path.expanduser("~/workspace/bin/trivy")
TIMEOUT = 300

sys.path.insert(0, FINAL_EVAL)
from timing_harness import time_project


def trivy_cmd(pid):
    target = os.path.join(CORPUS, pid)
    out = os.path.join(OUT, "timing-tmp", f"{pid}.json")
    return [TRIVY, "config", "--skip-version-check", "--skip-check-update",
            "--format", "json", "--output", out, target]


def warmup():
    empty = os.path.join(OUT, "timing-tmp", "empty-dir")
    os.makedirs(empty, exist_ok=True)
    print("warm-up: throwaway scan of an empty dir ...", flush=True)
    subprocess.run([TRIVY, "config", "--skip-version-check", "--skip-check-update",
                    "--format", "json", "--output",
                    os.path.join(OUT, "timing-tmp", "warmup.json"), empty],
                   capture_output=True, text=True, timeout=TIMEOUT)
    print("warm-up done", flush=True)


def main():
    os.makedirs(os.path.join(OUT, "timing-tmp"), exist_ok=True)
    with open(os.path.join(FINAL_EVAL, "timing-subset.json")) as f:
        subset = json.load(f)
    warmup()
    timing = {}
    for i, pid in enumerate(subset, 1):
        rec = time_project(trivy_cmd(pid), runs=5, timeout=TIMEOUT)
        timing[pid] = rec
        walls = [rec["cold"]] + list(rec["warm"])
        warm_sorted = sorted(rec["warm"])
        warm_med = warm_sorted[len(warm_sorted) // 2] if warm_sorted else None
        print(f"[{i}/{len(subset)}] {pid}: cold={round(walls[0],2)}s "
              f"warm_med={round(warm_med,2) if warm_med is not None else '?'}s "
              f"rss={rec['peak_rss_kb']}kB exits={rec['exit_codes']}", flush=True)
        # flush incrementally so a crash doesn't lose progress
        tmp = os.path.join(OUT, "TIMING.json.tmp")
        with open(tmp, "w") as f:
            json.dump(timing, f, indent=2)
        os.replace(tmp, os.path.join(OUT, "TIMING.json"))
    print("TIMING.json written")


if __name__ == "__main__":
    sys.exit(main())
