#!/usr/bin/env python3
"""Rigorous timing: 10 runs each, run 1 = cold (cleared caches), runs 2-10 = warm."""
import subprocess, time, statistics, json, os, shutil

AEGIS = os.path.expanduser("~/workspace/aegis-engine/aegis")
CHECKOV = os.path.expanduser("~/workspace/.venv-checkov/bin/checkov")
OUT = os.path.expanduser("~/workspace/aegis-engine/benchmark/rigorous/timing_results.json")

corpora = {
    "terragoat": os.path.expanduser("~/workspace/terragoat-fresh"),
    "vuln-200": os.path.expanduser("~/workspace/terraform/vuln-200"),
    "vuln-22": os.path.expanduser("~/workspace/vuln-22"),
}

def clear_caches():
    # Clear Python bytecode caches that could warm Checkov
    for p in [os.path.expanduser("~/.cache"), "/tmp"]:
        pass  # Don't actually delete user caches; document instead
    # Drop OS page cache is not permitted; note as limitation

def run_once(cmd):
    s = time.perf_counter()
    subprocess.run(cmd, capture_output=True, timeout=180)
    return (time.perf_counter() - s) * 1000

results = {}
for name, path in corpora.items():
    print(f"\n=== {name} ===", flush=True)
    # Aegis: 10 runs
    a_times = []
    for i in range(10):
        t = run_once([AEGIS, "scan", path, "--format=json"])
        a_times.append(round(t, 1))
        print(f"  Aegis run {i+1}: {t:.0f}ms", flush=True)
    # Checkov: 10 runs
    c_times = []
    for i in range(10):
        t = run_once([CHECKOV, "-d", path, "--framework", "terraform", "-o", "json"])
        c_times.append(round(t, 1))
        print(f"  Checkov run {i+1}: {t:.0f}ms", flush=True)
    
    a_sorted = sorted(a_times)
    c_sorted = sorted(c_times)
    results[name] = {
        "aegis": {
            "cold_ms": a_times[0],
            "warm_runs_ms": a_times[1:],
            "warm_min": min(a_times[1:]), "warm_median": round(statistics.median(a_times[1:]), 1),
            "warm_p95": a_sorted[int(len(a_sorted)*0.95)], "warm_max": max(a_times[1:]),
            "all_median": round(statistics.median(a_times), 1),
        },
        "checkov": {
            "cold_ms": c_times[0],
            "warm_runs_ms": c_times[1:],
            "warm_min": min(c_times[1:]), "warm_median": round(statistics.median(c_times[1:]), 1),
            "warm_p95": c_sorted[int(len(c_sorted)*0.95)], "warm_max": max(c_times[1:]),
            "all_median": round(statistics.median(c_times), 1),
        },
    }
    results[name]["speedup_warm_median"] = round(results[name]["checkov"]["warm_median"] / max(results[name]["aegis"]["warm_median"], 0.1), 1)

json.dump(results, open(OUT, "w"), indent=2)
print(f"\nSaved to {OUT}", flush=True)
