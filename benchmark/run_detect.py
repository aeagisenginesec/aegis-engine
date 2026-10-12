#!/usr/bin/env python3
"""Fast detection-only benchmark: Aegis vs Checkov on held-out set. No timing pass."""
import os, json, subprocess, sys
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
    except Exception:
        return -1

def scan_checkov(proj_dir):
    try:
        r = subprocess.run([CHECKOV, "-d", proj_dir, "--framework", "terraform",
                           "-o", "json", "--quiet"],
                          capture_output=True, text=True, timeout=120)
        return json.loads(r.stdout)["summary"]["failed"]
    except Exception:
        return -1

results = {"aegis": {"tp":0,"fp":0,"fn":0,"tn":0,"errors":0},
           "checkov": {"tp":0,"fp":0,"fn":0,"tn":0,"errors":0}}

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

for name in ["aegis", "checkov"]:
    r = results[name]
    tp, fp, fn = r["tp"], r["fp"], r["fn"]
    prec = tp/(tp+fp) if tp+fp else 0
    rec = tp/(tp+fn) if tp+fn else 0
    r["precision"] = round(prec, 3); r["recall"] = round(rec, 3)
    r["f1"] = round(2*prec*rec/(prec+rec), 3) if prec+rec else 0
    print(f"{name}: P={r['precision']} R={r['recall']} F1={r['f1']} "
          f"TP={r['tp']} FP={r['fp']} FN={r['fn']} TN={r['tn']} err={r['errors']}", flush=True)

json.dump(results, open(os.path.join(BASE, "detect_results.json"), "w"), indent=2)
