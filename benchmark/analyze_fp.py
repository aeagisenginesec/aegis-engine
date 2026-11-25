#!/usr/bin/env python3
"""Per-rule analysis of held-out results: which rules fire on clean vs vulnerable projects.

False positives are counted on the MEDIUM+ standard (since 2026-11-25,
benchmark-authority fix): only medium+ findings on clean projects count
as FPs, matching the live `aegis quality-gate` and
benchmark/corpus-v2/score.py. Low/info hygiene findings on clean projects
are reported separately (hygiene_low_rules / clean_hygiene_projects) —
they are informational, not detection failures. See docs/BENCHMARKS.md.

Paths are relative to this script, so it runs from any checkout. Expects
the `aegis` binary at the repo root (build it first: go build -o aegis ./cmd/aegis).
"""
import datetime
import json
import os
import subprocess
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE, ".."))
HELDOUT = os.path.join(BASE, "heldout")
MANIFEST = {m["project"]: m for m in json.load(open(os.path.join(BASE, "heldout_manifest.json")))}
AEGIS = os.path.join(REPO_ROOT, "aegis")

ACTIONABLE = ("critical", "high", "medium")  # low/info hygiene excluded


def scan(proj_dir):
    try:
        r = subprocess.run([AEGIS, "scan", proj_dir, "--format=json"],
                           capture_output=True, text=True, timeout=30)
        findings = json.loads(r.stdout).get("findings", [])
        return [(f.get("rule_id", "?"), str(f.get("severity", "")).lower())
                for f in findings]
    except Exception:
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

fp_rules = Counter()        # medium+ rule -> # clean projects where it fired
hygiene_low_rules = Counter()  # low/info rule -> # clean projects where it fired
tp_rules = Counter()        # rule -> # vulnerable projects where it fired (any severity)
clean_fp_projects = defaultdict(list)       # project -> medium+ rules (real FPs)
clean_hygiene_projects = defaultdict(list)  # project -> low/info rules only
errors = 0
for p, rules in results.items():
    if rules is None:
        errors += 1
        continue
    m = MANIFEST[p]
    if m["vulnerable"]:
        for r, _ in set(rules):
            tp_rules[r] += 1
    else:
        actionable = sorted({r for r, s in rules if s in ACTIONABLE})
        hygiene = sorted({r for r, s in rules if s in ("low", "info")})
        if actionable:
            clean_fp_projects[p] = actionable
            for r in actionable:
                fp_rules[r] += 1
        if hygiene:
            clean_hygiene_projects[p] = hygiene
            for r in hygiene:
                hygiene_low_rules[r] += 1

print(f"errors: {errors}")
print(f"clean projects with medium+ findings (FP): {len(clean_fp_projects)}/60")
print(f"clean projects with low/info findings only (hygiene, excluded): "
      f"{len(clean_hygiene_projects)}/60")
vuln_found = sum(1 for p in tasks
                 if MANIFEST[p]["vulnerable"] and results[p] and
                 any(s in ACTIONABLE for _, s in results[p]))
print(f"vulnerable projects with >=1 medium+ finding: {vuln_found}/140")
print()
print("=== FP rules, medium+ (fired on clean projects) ===")
for rule, n in fp_rules.most_common(25):
    print(f"  {rule}: clean={n} vuln={tp_rules[rule]}")
print()
print("=== Hygiene low/info rules on clean projects (excluded from FP) ===")
for rule, n in hygiene_low_rules.most_common(25):
    print(f"  {rule}: clean={n} vuln={tp_rules[rule]}")
print()
# Clean projects grouped by which rules fired (for spot-checking)
out = {"standard": "medium+ FP (low/info hygiene reported separately)",
       "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
       "fp_rules": dict(fp_rules), "tp_rules": dict(tp_rules),
       "hygiene_low_rules": dict(hygiene_low_rules),
       "clean_fp_projects": {p: r for p, r in clean_fp_projects.items()},
       "clean_hygiene_projects": {p: r for p, r in clean_hygiene_projects.items()}}
json.dump(out, open(os.path.join(BASE, "fp_analysis.json"), "w"), indent=1)
print("wrote fp_analysis.json")
