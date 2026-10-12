#!/usr/bin/env python3
import os, json, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
BASE = os.path.expanduser("~/workspace/aegis-engine/benchmark/rigorous")
HELDOUT = os.path.join(BASE, "heldout2")
MANIFEST = json.load(open(os.path.join(BASE, "heldout2_manifest.json")))
AEGIS = os.path.expanduser("~/workspace/aegis-engine/aegis")
CHECKOV = os.path.expanduser("~/workspace/.venv-checkov/bin/checkov")

def scan(args):
    tool, d = args
    try:
        if tool == "aegis":
            r = subprocess.run([AEGIS, "scan", d, "--format=json"], capture_output=True, text=True, timeout=30)
            return len(json.loads(r.stdout).get("findings", []))
        else:
            r = subprocess.run([CHECKOV, "-d", d, "--framework", "terraform", "-o", "json"], capture_output=True, text=True, timeout=60)
            return json.loads(r.stdout)["summary"]["failed"]
    except:
        return -1

results = {"aegis": {"tp":0,"fp":0,"fn":0,"tn":0,"err":0}, "checkov": {"tp":0,"fp":0,"fn":0,"tn":0,"err":0}}
tasks = [(t, os.path.join(HELDOUT, m["project"]), m["vulnerable"]) for m in MANIFEST for t in ["aegis","checkov"]]
print(f"Running {len(tasks)} scans...", flush=True)
with ThreadPoolExecutor(max_workers=8) as ex:
    futs = {ex.submit(scan, (t,d)): (t,v) for t,d,v in tasks}
    done = 0
    for fut in as_completed(futs):
        t, is_vuln = futs[fut]
        c = fut.result()
        done += 1
        if done % 50 == 0: print(f"  {done}/{len(tasks)}", flush=True)
        r = results[t]
        if c < 0: r["err"] += 1; continue
        f = c > 0
        if is_vuln and f: r["tp"] += 1
        elif is_vuln: r["fn"] += 1
        elif f: r["fp"] += 1
        else: r["tn"] += 1

for t, r in results.items():
    tp,fp,fn = r["tp"],r["fp"],r["fn"]
    prec = tp/(tp+fp) if tp+fp else 0
    rec = tp/(tp+fn) if tp+fn else 0
    r["precision"] = round(prec,3); r["recall"] = round(rec,3)
    r["f1"] = round(2*prec*rec/(prec+rec),3) if prec+rec else 0

json.dump(results, open(os.path.join(BASE, "heldout2_results.json"),"w"), indent=2)
print(json.dumps(results, indent=2), flush=True)
