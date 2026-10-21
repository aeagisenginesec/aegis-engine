#!/usr/bin/env python3
"""Item 6b perf harness: fork/exec per run, wall time + peak RSS via wait4 ru_maxrss.
Usage: perf_run.py <dir> <runs> [label]  -> prints one JSON line per run + summary.
Aegis JSON output is parsed for findings/resources/completeness; stdout is
piped and fully consumed. Caching: no aegis-level cache exists (verified:
no cache dir/env in --help); OS page cache is warm for all runs except the
first exec after build (reported as run 1)."""
import os, sys, time, json, subprocess, statistics

BIN = "/tmp/aegis-item6b/aegis"

def run_once(target):
    t0 = time.time()
    # Use subprocess with a fork to get wait4 rusage: Popen doesn't expose it,
    # so fork manually.
    rpipe, wpipe = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(rpipe)
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(wpipe, 1)
            os.dup2(devnull, 2)
            os.execv(BIN, [BIN, "scan", target, "--format=json"])
        except Exception:
            os._exit(127)
    os.close(wpipe)
    chunks = []
    while True:
        try:
            b = os.read(rpipe, 1 << 20)
        except OSError:
            break
        if not b:
            break
        chunks.append(b)
    os.close(rpipe)
    _, status, ru = os.wait4(pid, 0)
    wall = time.time() - t0
    out = b"".join(chunks)
    findings = resources = None
    comp = {}
    try:
        doc = json.loads(out)
        findings = len(doc.get("findings", []))
        resources = doc.get("resources_scanned")
        comp = doc.get("scan_completeness", {})
    except Exception as e:
        print(f"WARN unparsable output ({len(out)} bytes): {e}", file=sys.stderr)
    return {"wall_ms": wall * 1000, "rss_mb": ru.ru_maxrss / 1024.0,
            "exit": os.waitstatus_to_exitcode(status), "findings": findings,
            "resources": resources, "files": comp.get("files_discovered"),
            "out_bytes": len(out)}

def pct(sorted_vals, p):
    if not sorted_vals:
        return None
    i = min(len(sorted_vals) - 1, max(0, int(p / 100.0 * len(sorted_vals))))
    return sorted_vals[i]

def main():
    target, runs = sys.argv[1], int(sys.argv[2])
    label = sys.argv[3] if len(sys.argv) > 3 else target
    rows = []
    for i in range(runs):
        r = run_once(target)
        r["run"] = i + 1
        r["label"] = label
        rows.append(r)
        print(json.dumps(r), flush=True)
    walls = sorted(r["wall_ms"] for r in rows)
    rss = sorted(r["rss_mb"] for r in rows)
    nfiles = rows[0]["files"] or 0
    nres = rows[0]["resources"] or 0
    print(json.dumps({
        "summary": label, "runs": runs, "files": nfiles, "resources": nres,
        "findings": rows[0]["findings"],
        "wall_min_ms": walls[0], "wall_p50_ms": pct(walls, 50),
        "wall_p95_ms": pct(walls, 95), "wall_p99_ms": pct(walls, 99),
        "wall_max_ms": walls[-1], "wall_mean_ms": statistics.mean(walls),
        "rss_p50_mb": pct(rss, 50), "rss_max_mb": rss[-1],
        "files_per_s_p50": (nfiles / (pct(walls, 50) / 1000.0)) if pct(walls, 50) else None,
        "resources_per_s_p50": (nres / (pct(walls, 50) / 1000.0)) if pct(walls, 50) and nres else None,
    }), flush=True)

if __name__ == "__main__":
    main()
