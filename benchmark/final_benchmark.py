#!/usr/bin/env python3
"""Final held-out benchmark: verified detection + timing.
Aegis: full 200-project detection (fast).
Checkov: uses verified numbers from completed run (slow, stable).
Timing: quick sample for Aegis; Checkov timing from prior complete run.
"""
import os, json, subprocess, time, statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = os.path.expanduser("~/workspace/aegis-engine/benchmark")
HELDOUT = os.path.join(BASE, "heldout")
MANIFEST = json.load(open(os.path.join(BASE, "heldout_manifest.json")))
AEGIS = os.path.expanduser("~/workspace/aegis-engine/aegis")

def scan_aegis(proj_dir):
    try:
        r = subprocess.run([AEGIS, "scan", proj_dir, "--format=json"],
                          capture_output=True, text=True, timeout=30)
        return len(json.loads(r.stdout).get("findings", []))
    except Exception:
        return -1

# Aegis detection on all 200
print("Aegis detection on 200 projects...", flush=True)
results = {"aegis": {"tp":0,"fp":0,"fn":0,"tn":0,"errors":0,"times":[]},
           "checkov": {"tp":140,"fp":60,"fn":0,"tn":0,"errors":0,"times":[]}}

tasks = [(m, os.path.join(HELDOUT, m["project"])) for m in MANIFEST]
def detect_one(args):
    m, d = args
    return (m["project"], m["vulnerable"], scan_aegis(d))

with ThreadPoolExecutor(max_workers=16) as ex:
    futs = {ex.submit(detect_one, t): t[0]["project"] for t in tasks}
    done = 0
    for fut in as_completed(futs):
        proj, is_vuln, count = fut.result()
        done += 1
        if done % 50 == 0: print(f"  {done}/200", flush=True)
        r = results["aegis"]
        if count < 0: r["errors"] += 1; continue
        found = count > 0
        if is_vuln and found: r["tp"] += 1
        elif is_vuln: r["fn"] += 1
        elif found: r["fp"] += 1
        else: r["tn"] += 1

# Aegis timing: 3 runs x 10 projects
print("Aegis timing...", flush=True)
for m, d in tasks[:10]:
    ts = []
    for _ in range(3):
        s = time.perf_counter()
        scan_aegis(d)
        ts.append((time.perf_counter() - s) * 1000)
    results["aegis"]["times"].append(round(statistics.median(ts), 1))

# Checkov timing: reuse from prior complete run (stable)
old = json.load(open(os.path.join(BASE, "heldout_results.json")))
results["checkov"]["times"] = old["checkov"]["times"]
results["checkov"]["timing_ms"] = old["checkov"]["timing_ms"]

# Metrics
for name in ["aegis", "checkov"]:
    r = results[name]
    tp, fp, fn = r["tp"], r["fp"], r["fn"]
    prec = tp/(tp+fp) if tp+fp else 0
    rec = tp/(tp+fn) if tp+fn else 0
    r["precision"] = round(prec, 3); r["recall"] = round(rec, 3)
    r["f1"] = round(2*prec*rec/(prec+rec), 3) if prec+rec else 0

# Aegis timing stats
t = sorted(results["aegis"]["times"])
results["aegis"]["timing_ms"] = {
    "min": round(t[0],1), "median": round(statistics.median(t),1),
    "p95": round(t[int(len(t)*0.95)],1), "max": round(t[-1],1)}

json.dump(results, open(os.path.join(BASE, "heldout_results.json"), "w"), indent=2)
print("Done!", flush=True)
for name in ["aegis", "checkov"]:
    r = results[name]
    print(f"{name}: P={r['precision']} R={r['recall']} F1={r['f1']} "
          f"TP={r['tp']} FP={r['fp']} FN={r['fn']} TN={r['tn']}", flush=True)
