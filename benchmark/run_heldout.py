#!/usr/bin/env python3
"""Phase 5: Held-out benchmark. Aegis vs Checkov. 200 projects, 5 timing runs each."""
import os, json, subprocess, time, statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = os.path.expanduser("~/workspace/aegis-engine/benchmark")
HELDOUT = os.path.join(BASE, "heldout")
MANIFEST = json.load(open(os.path.join(BASE, "heldout_manifest.json")))
AEGIS = os.path.expanduser("~/workspace/aegis-engine/aegis")
CHECKOV = os.path.expanduser("~/workspace/.venv-checkov/bin/checkov")

def scan_aegis(proj_dir):
    try:
        r = subprocess.run([AEGIS, "scan", proj_dir, "--format=json"],
                          capture_output=True, text=True, timeout=30)
        return len(json.loads(r.stdout).get("findings", []))
    except: return -1

def scan_checkov(proj_dir):
    try:
        r = subprocess.run([CHECKOV, "-d", proj_dir, "--framework", "terraform",
                           "-o", "json", "--quiet"],
                          capture_output=True, text=True, timeout=120)
        return json.loads(r.stdout)["summary"]["failed"]
    except: return -1

def time_runs(fn, proj_dir, runs=5):
    times = []
    for _ in range(runs):
        s = time.perf_counter()
        fn(proj_dir)
        times.append((time.perf_counter() - s) * 1000)
    times.sort()
    return {"min": round(times[0],1), "median": round(statistics.median(times),1),
            "p95": round(times[int(len(times)*0.95)],1), "max": round(times[-1],1)}

print("Phase 5: scanning 200 held-out projects...", flush=True)
results = {"aegis": {"tp":0,"fp":0,"fn":0,"tn":0,"errors":0,"times":[]},
           "checkov": {"tp":0,"fp":0,"fn":0,"tn":0,"errors":0,"times":[]}}

# Detection pass (parallel)
tasks = [(m, os.path.join(HELDOUT, m["project"])) for m in MANIFEST]
def detect_one(args):
    m, d = args
    return (m["project"], m["vulnerable"], scan_aegis(d), scan_checkov(d))

with ThreadPoolExecutor(max_workers=8) as ex:
    futs = {ex.submit(detect_one, t): t[0]["project"] for t in tasks}
    done = 0
    for fut in as_completed(futs):
        proj, is_vuln, a_count, c_count = fut.result()
        done += 1
        if done % 50 == 0: print(f"  {done}/200", flush=True)
        for name, count in [("aegis", a_count), ("checkov", c_count)]:
            r = results[name]
            if count < 0: r["errors"] += 1; continue
            found = count > 0
            if is_vuln and found: r["tp"] += 1
            elif is_vuln: r["fn"] += 1
            elif found: r["fp"] += 1
            else: r["tn"] += 1

# Timing pass: 5 runs each on a 20-project sample (full 200 x 5 would take hours for Checkov)
sample = tasks[:20]
print("Timing pass: 5 runs x 20 projects per tool...", flush=True)
for m, d in sample:
    results["aegis"]["times"].append(time_runs(scan_aegis, d)["median"])
    results["checkov"]["times"].append(time_runs(scan_checkov, d)["median"])

for name in ["aegis", "checkov"]:
    r = results[name]
    tp, fp, fn = r["tp"], r["fp"], r["fn"]
    prec = tp/(tp+fp) if tp+fp else 0
    rec = tp/(tp+fn) if tp+fn else 0
    r["precision"] = round(prec, 3); r["recall"] = round(rec, 3)
    r["f1"] = round(2*prec*rec/(prec+rec), 3) if prec+rec else 0
    t = sorted(r["times"])
    if t:
        r["timing_ms"] = {"min": round(t[0],1), "median": round(statistics.median(t),1),
                         "p95": round(t[int(len(t)*0.95)],1), "max": round(t[-1],1)}

json.dump(results, open(os.path.join(BASE, "heldout_results.json"), "w"), indent=2)
print("Done!", flush=True)
for name in ["aegis", "checkov"]:
    r = results[name]
    print(f"{name}: P={r['precision']} R={r['recall']} F1={r['f1']} "
          f"TP={r['tp']} FP={r['fp']} FN={r['fn']} TN={r['tn']} err={r['errors']}")
    if "timing_ms" in r: print(f"  timing: {r['timing_ms']}")
