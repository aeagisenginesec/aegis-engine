#!/usr/bin/env python3
"""Final held-out benchmark: verified detection + timing (fast refresh path).

Re-scans Aegis on all 200 phase-5 held-out projects and rewrites
benchmark/heldout_results.json. Checkov numbers are reused from the prior
complete run (slow, stable) — see benchmark/run_heldout.py for the full
re-run including Checkov detection + timing.

Detection standard (since 2026-11-25, benchmark-authority fix): Aegis
counts a project as "found" iff it has >=1 MEDIUM+ finding; low/info
hygiene findings are reported separately (hygiene_low_fp) and do NOT
count as false positives. This matches the live `aegis quality-gate`
and benchmark/corpus-v2/score.py — see docs/BENCHMARKS.md.

Paths are relative to this script, so it runs from any checkout. Expects
the `aegis` binary at the repo root (build it first: go build -o aegis ./cmd/aegis).
"""
import datetime
import json
import os
import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE, ".."))
HELDOUT = os.path.join(BASE, "heldout")
MANIFEST = json.load(open(os.path.join(BASE, "heldout_manifest.json")))
AEGIS = os.path.join(REPO_ROOT, "aegis")

ACTIONABLE = ("critical", "high", "medium")  # low/info hygiene excluded


def scan_aegis(proj_dir):
    """Returns (actionable_count, hygiene_count) or (-1, -1) on error."""
    try:
        r = subprocess.run([AEGIS, "scan", proj_dir, "--format=json"],
                           capture_output=True, text=True, timeout=30)
        findings = json.loads(r.stdout).get("findings", [])
    except Exception:
        return -1, -1
    actionable = sum(1 for f in findings
                     if str(f.get("severity", "")).lower() in ACTIONABLE)
    hygiene = sum(1 for f in findings
                  if str(f.get("severity", "")).lower() in ("low", "info"))
    return actionable, hygiene


# Aegis detection on all 200
print("Aegis detection on 200 projects...", flush=True)
results = {"aegis": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "errors": 0,
                     "hygiene_low_fp": 0, "times": []}}

tasks = [(m, os.path.join(HELDOUT, m["project"])) for m in MANIFEST]


def detect_one(args):
    m, d = args
    return (m["project"], m["vulnerable"], scan_aegis(d))


with ThreadPoolExecutor(max_workers=16) as ex:
    futs = {ex.submit(detect_one, t): t[0]["project"] for t in tasks}
    done = 0
    for fut in as_completed(futs):
        proj, is_vuln, (count, hygiene) = fut.result()
        done += 1
        if done % 50 == 0:
            print(f"  {done}/200", flush=True)
        r = results["aegis"]
        if count < 0:
            r["errors"] += 1
            continue
        found = count > 0
        if is_vuln and found:
            r["tp"] += 1
        elif is_vuln:
            r["fn"] += 1
        elif found:
            r["fp"] += 1
        else:
            r["tn"] += 1
        if not is_vuln:
            r["hygiene_low_fp"] += hygiene

# Aegis timing: 3 runs x 10 projects
print("Aegis timing...", flush=True)
for m, d in tasks[:10]:
    ts = []
    for _ in range(3):
        s = time.perf_counter()
        scan_aegis(d)
        ts.append((time.perf_counter() - s) * 1000)
    results["aegis"]["times"].append(round(statistics.median(ts), 1))

# Checkov: reuse detection + timing from prior complete run (stable).
# Never hardcode Checkov numbers here; they come from the stored file.
old = json.load(open(os.path.join(BASE, "heldout_results.json")))
results["checkov"] = old["checkov"]

# Metrics
for name in ["aegis", "checkov"]:
    r = results[name]
    tp, fp, fn = r["tp"], r["fp"], r["fn"]
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    r["precision"] = round(prec, 3)
    r["recall"] = round(rec, 3)
    r["f1"] = round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0

# Aegis timing stats
t = sorted(results["aegis"]["times"])
results["aegis"]["timing_ms"] = {
    "min": round(t[0], 1), "median": round(statistics.median(t), 1),
    "p95": round(t[int(len(t) * 0.95)], 1), "max": round(t[-1], 1)}

results["_meta"] = {
    "generator": "benchmark/final_benchmark.py (aegis-only refresh; "
                 "checkov block reused from prior complete run)",
    "standard": "aegis: >=1 medium+ finding counts as found; low/info hygiene "
                "excluded and reported as hygiene_low_fp. checkov: any failed "
                "check counts (no severity in Checkov JSON).",
    "corpus": "benchmark/heldout, 200 projects (140 vulnerable / 60 clean), seed 999",
    "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
try:
    results["_meta"]["aegis_version"] = subprocess.run(
        [AEGIS, "--version"], capture_output=True, text=True,
        timeout=30).stdout.strip()
    results["_meta"]["git_commit"] = subprocess.run(
        ["git", "-C", REPO_ROOT, "rev-parse", "--short", "HEAD"],
        capture_output=True, text=True, timeout=30).stdout.strip()
except Exception:
    pass

json.dump(results, open(os.path.join(BASE, "heldout_results.json"), "w"), indent=2)
print("Done!", flush=True)
for name in ["aegis", "checkov"]:
    r = results[name]
    print(f"{name}: P={r['precision']} R={r['recall']} F1={r['f1']} "
          f"TP={r['tp']} FP={r['fp']} FN={r['fn']} TN={r['tn']}", flush=True)
print(f"aegis hygiene_low_fp (low/info findings on clean projects, excluded): "
      f"{results['aegis']['hygiene_low_fp']}")
