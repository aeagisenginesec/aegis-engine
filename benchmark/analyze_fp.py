#!/usr/bin/env python3
"""Per-rule analysis of held-out results: which rules fire on clean vs vulnerable projects."""
import os, json, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter, defaultdict

BASE = os.path.expanduser("~/workspace/aegis-engine/benchmark")
HELDOUT = os.path.join(BASE, "heldout")
MANIFEST = {m["project"]: m for m in json.load(open(os.path.join(BASE, "heldout_manifest.json")))}
AEGIS = os.path.expanduser("~/workspace/aegis-engine/aegis")

def scan(proj_dir):
    try:
        r = subprocess.run([AEGIS, "scan", proj_dir, "--format=json"],
                          capture_output=True, text=True, timeout=30)
        findings = json.loads(r.stdout).get("findings", [])
        return [f.get("rule_id", "?") for f in findings]
    except Exception as e:
        return None

results = {}
tasks = list(MANIFEST.keys())
def one(p):
    return p, scan(os.path.join(HELDOUT, p))

with ThreadPoolExecutor(max_workers=16) as ex:
    futs = {ex.submit(one, p): p for p in tasks}
    for fut in as_completed(futs):
        p, rules = fut.result()
        results[p] = rules

fp_rules = Counter()   # rule -> # clean projects where it fired
tp_rules = Counter()   # rule -> # vulnerable projects where it fired
clean_fp_projects = defaultdict(list)  # project -> rules
errors = 0
for p, rules in results.items():
    if rules is None:
        errors += 1
        continue
    m = MANIFEST[p]
    if m["vulnerable"]:
        for r in set(rules):
            tp_rules[r] += 1
    else:
        if rules:
            clean_fp_projects[p] = rules
            for r in set(rules):
                fp_rules[r] += 1

print(f"errors: {errors}")
print(f"clean projects with findings: {len(clean_fp_projects)}/60")
vuln_found = sum(1 for p in tasks if MANIFEST[p]["vulnerable"] and results[p])
print(f"vulnerable projects with >=1 finding: {vuln_found}/140")
print()
print("=== Top FP rules (fired on clean projects) ===")
for rule, n in fp_rules.most_common(25):
    print(f"  {rule}: clean={n} vuln={tp_rules[rule]}")
print()
# Clean projects grouped by which rules fired (for spot-checking)
out = {"fp_rules": dict(fp_rules), "tp_rules": dict(tp_rules),
       "clean_fp_projects": {p: r for p, r in clean_fp_projects.items()}}
json.dump(out, open(os.path.join(BASE, "fp_analysis.json"), "w"), indent=1)
print("wrote fp_analysis.json")
