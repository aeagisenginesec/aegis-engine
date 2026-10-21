#!/usr/bin/env python3
"""Shared timing harness for round-2 scanner sweeps.

Usage (import or copy):
    from timing_harness import time_project
    rec = time_project(["checkov", "-d", projdir, "-o", "json", "--quiet"],
                       cwd=None, runs=5, timeout=600)
    # -> {"cold": 9.81, "warm": [9.55, 9.62, 9.48, 9.60], "peak_rss_kb": 412340,
    #     "exit_codes": [1,1,1,1,1]}

Single-run variant (KICS documented deviation):
    rec = time_project(cmd, runs=1)
    # -> {"single_run": 40.2, "peak_rss_kb": 128068, "exit_codes": [0]}

Wall time via time.perf_counter(); peak RSS via resource.getrusage(RUSAGE_CHILDREN)
(max resident set size of waited-for children, in KB on Linux).
Run 1 is the cold run (fresh process, caches cold); runs 2-5 are warm.
"""
import subprocess
import time
import resource
import os


def _peak_rss_children_kb():
    # ru_maxrss is kilobytes on Linux
    return resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss


def time_project(cmd, cwd=None, runs=5, timeout=900, env=None):
    walls, codes = [], []
    peak = 0
    for _ in range(runs):
        start = time.perf_counter()
        try:
            p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout,
                               env=env)
            codes.append(p.returncode)
        except subprocess.TimeoutExpired:
            codes.append('timeout')
        walls.append(time.perf_counter() - start)
        peak = max(peak, _peak_rss_children_kb())
    rec = {"peak_rss_kb": int(peak), "exit_codes": codes}
    if runs == 1:
        rec["single_run"] = walls[0]
    else:
        rec["cold"] = walls[0]
        rec["warm"] = walls[1:]
    return rec


if __name__ == "__main__":
    import sys, json
    # smoke test: time `true`
    print(json.dumps(time_project(["true"], runs=2), indent=1))
