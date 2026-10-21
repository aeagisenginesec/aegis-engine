#!/usr/bin/env python3
"""Checkov 3.3.26 timing sweep: 5 runs per timing-subset project (run 1 = cold).

Uses timing_harness.time_project with runs=5, timeout=300.
Writes <out>/TIMING.json as {"<id>": {"cold": s, "warm": [s,s,s,s], "peak_rss_kb": N, "exit_codes": [...]}}.
Also writes TIMING_META.json with start/end timestamps and the exact command.
Resume-safe: ids already in TIMING.json are skipped.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval"))
from timing_harness import time_project  # noqa: E402

EVAL = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval")
CORPUS = os.path.join(EVAL, "corpus")
OUT = os.path.join(EVAL, "scanner-output/checkov")
CHECKOV = os.path.expanduser("~/workspace/.venv-checkov/bin/checkov")
TIMEOUT = 300


def main():
    os.makedirs(OUT, exist_ok=True)
    timing_path = os.path.join(OUT, "TIMING.json")
    meta_path = os.path.join(OUT, "TIMING_META.json")

    with open(os.path.join(EVAL, "timing-subset.json")) as f:
        subset = json.load(f)

    timing = json.load(open(timing_path)) if os.path.exists(timing_path) else {}
    todo = [i for i in subset if i not in timing]

    start_wall = time.time()
    start_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"[timing] {len(todo)} to time (skipped {len(subset) - len(todo)} done) | start {start_iso}", flush=True)

    for n, pid in enumerate(todo, 1):
        pdir = os.path.join(CORPUS, pid)
        cmd = [CHECKOV, "-d", pdir, "-o", "json", "--quiet"]
        rec = time_project(cmd, cwd=None, runs=5, timeout=TIMEOUT)
        timing[pid] = {
            "cold": rec["cold"],
            "warm": rec["warm"],
            "peak_rss_kb": rec["peak_rss_kb"],
            "exit_codes": rec["exit_codes"],
        }
        json.dump(timing, open(timing_path, "w"), indent=1)
        print(f"[{n}/{len(todo)}] {pid}: cold={rec['cold']:.1f}s warm={[f'{w:.1f}' for w in rec['warm']]} rss={rec['peak_rss_kb']}KB codes={rec['exit_codes']}", flush=True)

    end_wall = time.time()
    end_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    json.dump({
        "command": f"{CHECKOV} -d <corpus>/<id> -o json --quiet",
        "runs": 5, "timeout_s": TIMEOUT,
        "start_iso": start_iso, "end_iso": end_iso,
        "wall_s": round(end_wall - start_wall, 1),
        "n_projects": len(timing),
    }, open(meta_path, "w"), indent=1)
    print(f"[timing] DONE: {len(timing)} projects, wall={(end_wall - start_wall)/60:.1f} min", flush=True)


if __name__ == "__main__":
    main()
