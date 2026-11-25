#!/usr/bin/env python3
"""Phase 5: Held-out benchmark. Aegis vs Checkov. 200 projects, 5 timing runs each.

Regenerates benchmark/heldout_results.json — the stored authority for the
phase-5 held-out corpus (see docs/BENCHMARKS.md).

Detection standard (since 2026-11-25, benchmark-authority fix):
  - Aegis: a project counts as "found" iff it has >=1 MEDIUM+ finding.
    Low/info hygiene findings are informational and reported separately
    (hygiene_low_fp); they do NOT count as false positives. This matches
    the live `aegis quality-gate` (internal/qualitygate/benchmark.go) and
    benchmark/corpus-v2/score.py. The old any-finding standard counted
    deliberate low rules (e.g. AEGIS-AWS-742/852) as FPs and produced the
    FP=60 vs FP=0 contradiction resolved in docs/BENCHMARKS.md.
  - Checkov: any failed check counts (Checkov's JSON carries no severity,
    so its numbers are upper bounds — same methodology as CORPUS_V2.md).

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
CHECKOV = os.path.expanduser("~/workspace/.venv-checkov/bin/checkov")

ACTIONABLE = ("critical", "high", "medium")  # low/info hygiene excluded


def aegis_findings(proj_dir):
    try:
        r = subprocess.run([AEGIS, "scan", proj_dir, "--format=json"],
                           capture_output=True, text=True, timeout=30)
        return json.loads(r.stdout).get("findings", [])
    except Exception:
        return None


def scan_aegis(proj_dir):
    """Returns (actionable_count, hygiene_count) or (-1, -1) on error."""
    findings = aegis_findings(proj_dir)
    if findings is None:
        return -1, -1
    actionable = sum(1 for f in findings
                     if str(f.get("severity", "")).lower() in ACTIONABLE)
    hygiene = sum(1 for f in findings
                  if str(f.get("severity", "")).lower() in ("low", "info"))
    return actionable, hygiene


def scan_checkov(proj_dir):
    try:
        r = subprocess.run([CHECKOV, "-d", proj_dir, "--framework", "terraform",
                            "-o", "json", "--quiet"],
                           capture_output=True, text=True, timeout=120)
        return json.loads(r.stdout)["summary"]["failed"]
    except Exception:
        return -1


def time_runs(fn, proj_dir, runs=5):
    times = []
    for _ in range(runs):
        s = time.perf_counter()
        fn(proj_dir)
        times.append((time.perf_counter() - s) * 1000)
    times.sort()
    return {"min": round(times[0], 1), "median": round(statistics.median(times), 1),
            "p95": round(times[int(len(times) * 0.95)], 1), "max": round(times[-1], 1)}


def tool_meta():
    meta = {"generator": "benchmark/run_heldout.py",
            "standard": "aegis: >=1 medium+ finding counts as found; "
                        "low/info hygiene excluded and reported as hygiene_low_fp. "
                        "checkov: any failed check counts (no severity in Checkov JSON).",
            "corpus": "benchmark/heldout, 200 projects (140 vulnerable / 60 clean), seed 999",
            "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        meta["aegis_version"] = subprocess.run(
            [AEGIS, "--version"], capture_output=True, text=True,
            timeout=30).stdout.strip()
    except Exception:
        pass
    try:
        meta["git_commit"] = subprocess.run(
            ["git", "-C", REPO_ROOT, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        pass
    try:
        out = subprocess.run([AEGIS, "doctor"], capture_output=True, text=True,
                             timeout=60).stdout
        for line in out.splitlines():
            if "rules loaded" in line:
                meta["aegis_rules"] = line.strip()
                break
    except Exception:
        pass
    return meta


print("Phase 5: scanning 200 held-out projects...", flush=True)
results = {"aegis": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "errors": 0,
                     "hygiene_low_fp": 0},
           "checkov": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "errors": 0, "times": []}}

# Detection pass (parallel)
tasks = [(m, os.path.join(HELDOUT, m["project"])) for m in MANIFEST]


def detect_one(args):
    m, d = args
    a_actionable, a_hygiene = scan_aegis(d)
    return (m["project"], m["vulnerable"], a_actionable, a_hygiene, scan_checkov(d))


with ThreadPoolExecutor(max_workers=8) as ex:
    futs = {ex.submit(detect_one, t): t[0]["project"] for t in tasks}
    done = 0
    for fut in as_completed(futs):
        proj, is_vuln, a_count, a_hygiene, c_count = fut.result()
        done += 1
        if done % 50 == 0:
            print(f"  {done}/200", flush=True)
        r = results["aegis"]
        if a_count < 0:
            r["errors"] += 1
        else:
            found = a_count > 0
            if is_vuln and found:
                r["tp"] += 1
            elif is_vuln:
                r["fn"] += 1
            elif found:
                r["fp"] += 1
            else:
                r["tn"] += 1
            if not is_vuln:
                r["hygiene_low_fp"] += a_hygiene
        r = results["checkov"]
        if c_count < 0:
            r["errors"] += 1
        else:
            found = c_count > 0
            if is_vuln and found:
                r["tp"] += 1
            elif is_vuln:
                r["fn"] += 1
            elif found:
                r["fp"] += 1
            else:
                r["tn"] += 1

# Timing pass: 5 runs each on a 20-project sample (full 200 x 5 would take hours for Checkov)
sample = tasks[:20]
print("Timing pass: 5 runs x 20 projects per tool...", flush=True)
aegis_times, checkov_times = [], []
for m, d in sample:
    aegis_times.append(time_runs(lambda p: scan_aegis(p), d)["median"])
    checkov_times.append(time_runs(scan_checkov, d)["median"])
results["aegis"]["times"] = aegis_times
results["checkov"]["times"] = checkov_times

for name in ["aegis", "checkov"]:
    r = results[name]
    tp, fp, fn = r["tp"], r["fp"], r["fn"]
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    r["precision"] = round(prec, 3)
    r["recall"] = round(rec, 3)
    r["f1"] = round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0
    t = sorted(r["times"])
    if t:
        r["timing_ms"] = {"min": round(t[0], 1), "median": round(statistics.median(t), 1),
                          "p95": round(t[int(len(t) * 0.95)], 1), "max": round(t[-1], 1)}

results["_meta"] = tool_meta()
json.dump(results, open(os.path.join(BASE, "heldout_results.json"), "w"), indent=2)
print("Done!", flush=True)
for name in ["aegis", "checkov"]:
    r = results[name]
    print(f"{name}: P={r['precision']} R={r['recall']} F1={r['f1']} "
          f"TP={r['tp']} FP={r['fp']} FN={r['fn']} TN={r['tn']} err={r['errors']}")
    if "timing_ms" in r:
        print(f"  timing: {r['timing_ms']}")
print(f"aegis hygiene_low_fp (low/info findings on clean projects, excluded): "
      f"{results['aegis']['hygiene_low_fp']}")
