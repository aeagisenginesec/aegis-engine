#!/usr/bin/env python3
"""Phase 6 timing harness.

Runs `aegis scan <dir> --format=text` N times per target, measuring
wall-clock time and peak RSS per run.

Peak RSS: no /usr/bin/time on this box, so we fork/exec and use
os.wait4() rusage.ru_maxrss (kilobytes on Linux) - the same quantity
GNU time reports as "Maximum resident set size".

Cold vs warm: /proc/sys/vm/drop_caches is read-only in this sandbox, so
all runs are OS-page-cache warm. Run 1 of each target is the process
cold-start (first exec of the binary); runs 2..N are warm. Labeled
accordingly in the CSV.

Findings/resources per run are parsed from the text report's summary
line ("resources: R, findings: F").

Completeness (files discovered/parsed/skipped/failed) is measured with
one --format=json run per target and attached to every run row (the
counts are run-invariant; verified identical across runs).

Usage:
    python3 run_perf.py --aegis /tmp/aegis-p6 --runs 11 --out perf.csv \
        small=/tmp/p6/small medium=/tmp/p6/medium large=/tmp/p6/large
"""
import argparse
import csv
import json
import os
import re
import statistics
import subprocess
import sys
import time

SUMMARY_RE = re.compile(r"resources:\s*(\d+),\s*findings:\s*(\d+)")


def timed_scan(aegis, target, extra_args=()):
    """Run one scan; return (wall_ms, rss_kb, findings, resources)."""
    r_fd, w_fd = os.pipe()
    t0 = time.perf_counter_ns()
    pid = os.fork()
    if pid == 0:
        # child
        try:
            os.close(r_fd)
            os.dup2(w_fd, 1)
            os.dup2(w_fd, 2)
            os.close(w_fd)
            os.execv(aegis, [aegis, "scan", target, "--format=text"] + list(extra_args))
        except BaseException:
            os._exit(127)
    # parent
    os.close(w_fd)
    chunks = []
    while True:
        try:
            data = os.read(r_fd, 1 << 20)
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
    os.close(r_fd)
    _, status, rusage = os.wait4(pid, 0)
    wall_ms = (time.perf_counter_ns() - t0) / 1e6
    rss_kb = rusage.ru_maxrss  # kilobytes on Linux
    out = b"".join(chunks).decode("utf-8", "replace")
    m = SUMMARY_RE.search(out)
    findings = int(m.group(2)) if m else -1
    resources = int(m.group(1)) if m else -1
    if os.waitstatus_to_exitcode(status) not in (0, 1):
        print(f"WARNING: scan of {target} exited {status}", file=sys.stderr)
    return wall_ms, rss_kb, findings, resources


def completeness(aegis, target):
    """One JSON scan -> (discovered, parsed, skipped, failed)."""
    p = subprocess.run(
        [aegis, "scan", target, "--format=json"],
        capture_output=True, text=True, timeout=900,
    )
    d = json.loads(p.stdout)
    sc = d["scan_completeness"]
    return (sc["files_discovered"], sc["files_parsed"],
            sc["files_skipped"], sc["files_failed"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--aegis", required=True)
    ap.add_argument("--runs", type=int, default=11)
    ap.add_argument("--out", required=True)
    ap.add_argument("targets", nargs="+", help="name=path")
    args = ap.parse_args()

    rows = []
    for spec in args.targets:
        name, path = spec.split("=", 1)
        print(f"=== {name}: {path} ===", flush=True)
        disc, parsed, skipped, failed = completeness(args.aegis, path)
        print(f"    completeness: discovered={disc} parsed={parsed} "
              f"skipped={skipped} failed={failed}", flush=True)
        assert parsed + skipped + failed == disc, "completeness mismatch!"
        walls = []
        for run in range(1, args.runs + 1):
            wall_ms, rss_kb, findings, resources = timed_scan(args.aegis, path)
            cold_warm = "cold" if run == 1 else "warm"
            rows.append({
                "repo_size": name, "run": run,
                "wall_ms": round(wall_ms, 2), "rss_kb": rss_kb,
                "findings": findings, "resources": resources,
                "files_discovered": disc, "parsed": parsed,
                "skipped": skipped, "failed": failed,
                "cold_warm": cold_warm,
            })
            walls.append(wall_ms)
            print(f"    run {run:2d} [{cold_warm}]: {wall_ms:9.2f} ms  "
                  f"rss={rss_kb:7d} kB  findings={findings}", flush=True)
        walls_sorted = sorted(walls)
        print(f"    median={statistics.median(walls):.2f} ms  "
              f"p95={walls_sorted[int(0.95*(len(walls_sorted)-1))]:.2f} ms",
              flush=True)

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "repo_size", "run", "wall_ms", "rss_kb", "findings",
            "resources", "files_discovered", "parsed", "skipped",
            "failed", "cold_warm"])
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {args.out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
