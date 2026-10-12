#!/usr/bin/env python3
"""For each vulnerable project, record the set of firing rules.
Then simulate removing candidate rules: which projects would drop to zero findings?"""
import os, json, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

BASE = os.path.expanduser("~/workspace/aegis-engine/benchmark")
HELDOUT = os.path.join(BASE, "heldout")
MANIFEST = {m["project"]: m for m in json.load(open(os.path.join(BASE, "heldout_manifest.json")))}
AEGIS = "/tmp/aegis_test"

def scan(proj_dir):
    try:
        r = subprocess.run([AEGIS, "scan", proj_dir, "--format=json"],
                          capture_output=True, text=True, timeout=30)
        return sorted(set(f.get("rule_id", "?") for f in json.loads(r.stdout).get("findings", [])))
    except Exception:
        return None

vuln_projects = [p for p, m in MANIFEST.items() if m["vulnerable"]]
results = {}
with ThreadPoolExecutor(max_workers=16) as ex:
    futs = {ex.submit(scan, os.path.join(HELDOUT, p)): p for p in vuln_projects}
    for fut in as_completed(futs):
        p = futs[fut]
        results[p] = fut.result()

# sole-detector analysis: projects where only one rule fires
sole = Counter()
for p, rules in results.items():
    if rules is None:
        print("ERROR scan failed:", p)
    elif len(rules) == 0:
        print("ZERO findings (FN!):", p, MANIFEST[p]["expected"])
    elif len(rules) == 1:
        sole[rules[0]] += 1

print("=== projects detected by exactly ONE rule (load-bearing) ===")
for rule, n in sole.most_common():
    print(f"  {rule}: {n}")

# simulate removing candidate noisy rules
candidates = ["AEGIS-AWS-558", "AEGIS-AWS-559", "AEGIS-AWS-602", "AEGIS-AWS-603",
              "AEGIS-AWS-445", "AEGIS-AWS-209", "AEGIS-AWS-001", "AEGIS-AWS-012",
              "AEGIS-AWS-206", "AEGIS-AWS-443", "AEGIS-AWS-601"]
cset = set(candidates)
lost = [p for p, rules in results.items() if rules and set(rules) <= cset]
print(f"\nprojects that would go to ZERO if all candidates removed: {len(lost)}")
for p in lost[:20]:
    print("  ", p, results[p], [e["vuln_id"] for e in MANIFEST[p]["expected"]])

json.dump({p: r for p, r in results.items()}, open(os.path.join(BASE, "vuln_rules.json"), "w"), indent=0)
