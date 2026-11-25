#!/usr/bin/env python3
"""Rigorous held-out benchmark: Aegis vs Checkov on the fresh 150-project
corpus (seed 20261012). Regenerates benchmark/rigorous/heldout2_results.json.

Detection standard (since 2026-11-25, benchmark-authority fix):
  - Aegis: a project counts as "found" iff it has >=1 MEDIUM+ finding.
    Low/info hygiene findings are reported separately (hygiene_low_fp)
    and do NOT count as false positives — same standard as the live
    `aegis quality-gate` and benchmark/corpus-v2/score.py.
  - Checkov: any failed check counts (no severity in Checkov JSON).

NOTE on this corpus: its 52 "clean" projects are minimal S3 setups
(bucket + SSE-KMS + KMS key) that were never hardened against the
medium/high rules — AEGIS-AWS-012 (no versioning), 206 (no public
access block), 443 (no secure transport) and 445 (no access logging)
correctly fire on all of them. The FP=52 in this file is therefore a
corpus-label fact (clean fixtures that are not actually hardened),
not a rule bug, and it reproduces unchanged on the current build.
See docs/BENCHMARKS.md and docs/RIGOROUS_BENCHMARK.md.

Paths are relative to this script, so it runs from any checkout. Expects
the `aegis` binary at the repo root (build it first: go build -o aegis ./cmd/aegis).
"""
import datetime
import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE, "..", ".."))
HELDOUT = os.path.join(BASE, "heldout2")
MANIFEST = json.load(open(os.path.join(BASE, "heldout2_manifest.json")))
AEGIS = os.path.join(REPO_ROOT, "aegis")
CHECKOV = os.path.expanduser("~/workspace/.venv-checkov/bin/checkov")

ACTIONABLE = ("critical", "high", "medium")  # low/info hygiene excluded


def scan(args):
    tool, d = args
    try:
        if tool == "aegis":
            r = subprocess.run([AEGIS, "scan", d, "--format=json"],
                               capture_output=True, text=True, timeout=30)
            findings = json.loads(r.stdout).get("findings", [])
            actionable = sum(1 for f in findings
                             if str(f.get("severity", "")).lower() in ACTIONABLE)
            hygiene = sum(1 for f in findings
                          if str(f.get("severity", "")).lower() in ("low", "info"))
            return actionable, hygiene
        else:
            r = subprocess.run([CHECKOV, "-d", d, "--framework", "terraform",
                                "-o", "json"], capture_output=True, text=True, timeout=60)
            return json.loads(r.stdout)["summary"]["failed"], 0
    except Exception:
        return -1, -1


results = {"aegis": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "err": 0,
                     "hygiene_low_fp": 0},
           "checkov": {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "err": 0}}
tasks = [(t, os.path.join(HELDOUT, m["project"]), m["vulnerable"])
         for m in MANIFEST for t in ["aegis", "checkov"]]
print(f"Running {len(tasks)} scans...", flush=True)
with ThreadPoolExecutor(max_workers=8) as ex:
    futs = {ex.submit(scan, (t, d)): (t, v) for t, d, v in tasks}
    done = 0
    for fut in as_completed(futs):
        t, is_vuln = futs[fut]
        c, hygiene = fut.result()
        done += 1
        if done % 50 == 0:
            print(f"  {done}/{len(tasks)}", flush=True)
        r = results[t]
        if c < 0:
            r["err"] += 1
            continue
        f = c > 0
        if is_vuln and f:
            r["tp"] += 1
        elif is_vuln:
            r["fn"] += 1
        elif f:
            r["fp"] += 1
        else:
            r["tn"] += 1
        if t == "aegis" and not is_vuln:
            r["hygiene_low_fp"] += hygiene

for t, r in results.items():
    tp, fp, fn = r["tp"], r["fp"], r["fn"]
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    r["precision"] = round(prec, 3)
    r["recall"] = round(rec, 3)
    r["f1"] = round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0

results["_meta"] = {
    "generator": "benchmark/rigorous/heldout2_run.py",
    "standard": "aegis: >=1 medium+ finding counts as found; low/info hygiene "
                "excluded and reported as hygiene_low_fp. checkov: any failed "
                "check counts (no severity in Checkov JSON).",
    "corpus": "benchmark/rigorous/heldout2, 150 projects (98 vulnerable / 52 clean), seed 20261012",
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

json.dump(results, open(os.path.join(BASE, "heldout2_results.json"), "w"), indent=2)
print(json.dumps(results, indent=2), flush=True)
