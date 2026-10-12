#!/usr/bin/env python3
"""Score corpus-v2 for Aegis, with KICS + Checkov comparison.

Usage: score.py [--skip-kics] [--skip-checkov] [--aegis-only]

Aegis (primary):
  - per-project `aegis scan --format=json`
  - project-level precision/recall/F1, FP rate (secure projects)
  - finding-level per-severity recall against expected (rule_id, resource, severity)
  - dev and held-out reported separately
  - known_gap projects excluded from recall denominators, reported separately
  - EXIT 1 if held-out F1 < 0.90

Comparison (context only):
  - Checkov + KICS run once per split directory; findings attributed per
    project via file paths. Project-level detection rate + secure FP rate.
  - KICS: medium+ = HIGH/MEDIUM. Checkov: severity is null in JSON, so all
    failed checks count (methodology difference noted in output).
"""
import argparse
import concurrent.futures
import glob
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
AEGIS = os.path.abspath(os.path.join(HERE, "..", "..", "aegis"))
CHECKOV = os.path.expanduser("~/workspace/.venv-checkov/bin/checkov")
KICS = os.path.expanduser("~/workspace/bin/kics")
KICS_QUERIES = os.path.expanduser("~/workspace/kics/assets/queries")

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
HELDOUT_F1_GATE = 0.90


def aegis_scan(project_dir):
    p = subprocess.run([AEGIS, "scan", "--format=json", project_dir],
                       capture_output=True, text=True, timeout=120)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"aegis scan failed for {project_dir}: exit={p.returncode} stderr={p.stderr[:300]}")


def scan_aegis_split(name, proj_dir, manifest):
    """Returns per-project results: {gid: {'found': {rule_id: (sev_rank, resource)}, 'ms': float}}"""
    results = {}
    errors = []

    def one(entry):
        gid = entry["project"]
        d = os.path.join(proj_dir, gid)
        t0 = time.time()
        try:
            res = aegis_scan(d)
            ms = (time.time() - t0) * 1000
            found = {}
            for f in res.get("findings", []):
                rid = f.get("rule_id", "")
                sev = str(f.get("severity", "")).lower()
                r = SEV_RANK.get(sev, 0)
                if r > found.get(rid, (0, ""))[0]:
                    found[rid] = (r, f.get("resource", ""))
            return gid, {"found": found, "ms": ms, "error": None}
        except Exception as e:  # noqa: BLE001
            return gid, {"found": {}, "ms": 0, "error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(one, e): e for e in manifest}
        for fut in concurrent.futures.as_completed(futs):
            gid, r = fut.result()
            results[gid] = r
            if r["error"]:
                errors.append((gid, r["error"]))
    return results, errors


def score_aegis(name, manifest, results):
    tp = fp = fn = 0
    n_vuln = n_secure = 0
    fn_projects, fp_projects = [], []
    sev_expected = {}   # severity -> [fired_bool]
    resource_mismatch = []
    gaps = []
    total_ms = 0

    by_gid = {e["project"]: e for e in manifest}
    for gid, r in results.items():
        entry = by_gid[gid]
        total_ms += r["ms"]
        found = r["found"]
        if entry.get("known_gap"):
            gaps.append(gid)
            continue
        expected = entry.get("expected", [])
        if entry["vulnerable"]:
            n_vuln += 1
            exp_ids = {e["rule_id"] for e in expected}
            if exp_ids & set(found):
                tp += 1
            else:
                fn += 1
                fn_projects.append((gid, sorted(exp_ids), sorted(found)))
            for e in expected:
                sev = str(e.get("severity", "")).lower()
                fired = e["rule_id"] in found
                sev_expected.setdefault(sev, []).append(fired)
                if fired:
                    exp_res = e.get("resource", "")
                    act_res = found[e["rule_id"]][1]
                    if exp_res and act_res and exp_res != act_res and exp_res not in act_res and act_res not in exp_res:
                        resource_mismatch.append((gid, e["rule_id"], exp_res, act_res))
        else:
            n_secure += 1
            med_plus = [rid for rid, (s, _) in found.items() if s >= SEV_RANK["medium"]]
            if med_plus:
                fp += 1
                fp_projects.append((gid, sorted(med_plus)))

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fp_rate = fp / n_secure if n_secure else 0.0
    sev_recall = {s: (sum(v) / len(v) if v else 0.0) for s, v in sev_expected.items()}
    avg_ms = total_ms / len(results) if results else 0
    return {
        "name": name, "n_vuln": n_vuln, "n_secure": n_secure,
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1, "fp_rate": fp_rate,
        "sev_recall": sev_recall, "avg_ms": avg_ms,
        "fn_projects": fn_projects, "fp_projects": fp_projects,
        "resource_mismatch": resource_mismatch, "known_gaps": gaps,
    }


def print_aegis_report(s):
    print(f"\n===== AEGIS [{s['name']}] =====")
    print(f"projects: {s['n_vuln']} vulnerable, {s['n_secure']} secure "
          f"(+{len(s['known_gaps'])} known_gap excluded)")
    print(f"TP={s['tp']}  FP={s['fp']}  FN={s['fn']}")
    print(f"precision          : {s['precision']:.3f}")
    print(f"recall             : {s['recall']:.3f}")
    print(f"F1                 : {s['f1']:.3f}")
    print(f"false-positive rate: {s['fp_rate']:.3f}")
    print(f"avg scan time      : {s['avg_ms']:.1f} ms/project")
    print("per-severity finding recall:")
    for sev in ("critical", "high", "medium", "low"):
        if sev in s["sev_recall"]:
            print(f"  {sev:8s}: {s['sev_recall'][sev]:.3f}")
    if s["fn_projects"]:
        print("--- FALSE NEGATIVES ---")
        for gid, exp, got in s["fn_projects"]:
            print(f"  {gid}: expected={exp} got={got}")
    if s["fp_projects"]:
        print("--- FALSE POSITIVES ---")
        for gid, rules in s["fp_projects"]:
            print(f"  {gid}: {rules}")
    if s["resource_mismatch"]:
        print("--- RESOURCE MISMATCH (rule fired, different resource) ---")
        for gid, rid, exp, act in s["resource_mismatch"]:
            print(f"  {gid} {rid}: expected={exp} actual={act}")
    if s["known_gaps"]:
        print(f"--- KNOWN SCANNER GAPS (excluded, documented) --- {s['known_gaps']}")


# ---------------------------------------------------------------- comparison
def run_checkov_bulk(scan_dir, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    t0 = time.time()
    p = subprocess.run([CHECKOV, "-d", scan_dir, "--framework", "terraform",
                        "--output", "json", "--output-file-path", out_dir,
                        "--quiet"],
                       capture_output=True, text=True, timeout=1200)
    ms = (time.time() - t0) * 1000
    files = glob.glob(os.path.join(out_dir, "*.json"))
    if not files:
        raise RuntimeError(f"checkov produced no output: {p.stderr[:300]}")
    d = json.load(open(files[0]))
    per_proj = {}
    for c in d.get("results", {}).get("failed_checks", []):
        fp = c.get("file_path", "")
        # file_path like /v2-000/main.tf -> project v2-000
        parts = [x for x in fp.split("/") if x]
        gid = parts[0] if parts else "?"
        per_proj.setdefault(gid, []).append(c.get("check_id"))
    return per_proj, ms


def run_kics_bulk(scan_dir, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    t0 = time.time()
    p = subprocess.run([KICS, "scan", "-p", scan_dir, "--no-progress", "--no-color",
                        "-o", out_dir, "--report-formats", "json",
                        "--queries-path", KICS_QUERIES],
                       capture_output=True, text=True, timeout=2400)
    ms = (time.time() - t0) * 1000
    rj = os.path.join(out_dir, "results.json")
    if not os.path.exists(rj):
        raise RuntimeError(f"kics produced no results.json: {p.stderr[:300]}")
    d = json.load(open(rj))
    per_proj = {}
    for q in d.get("queries", []):
        sev = str(q.get("severity", "")).upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM"):
            continue
        for f in q.get("files", []):
            fn = f.get("file_name", "")
            # file_name like projects/v2-000/main.tf or v2-000/main.tf
            parts = [x for x in fn.split("/") if x]
            gid = next((x for x in parts if x.startswith("v2-")), "?")
            per_proj.setdefault(gid, []).append(q.get("query_id"))
    failed = d.get("files_failed_to_scan") or []
    return per_proj, ms, len(failed)


def comparison_report(name, manifest, per_proj, tool, ms_total, extra=""):
    by_gid = {e["project"]: e for e in manifest}
    n_vuln = sum(1 for e in manifest if e["vulnerable"] and not e.get("known_gap"))
    n_sec = sum(1 for e in manifest if not e["vulnerable"])
    detected = sum(1 for e in manifest
                   if e["vulnerable"] and not e.get("known_gap") and per_proj.get(e["project"]))
    fp = sum(1 for e in manifest if not e["vulnerable"] and per_proj.get(e["project"]))
    det_rate = detected / n_vuln if n_vuln else 0
    fp_rate = fp / n_sec if n_sec else 0
    avg_ms = ms_total / len(manifest) if manifest else 0
    print(f"  {tool:8s} detection rate: {det_rate:.3f} ({detected}/{n_vuln})  "
          f"secure FP rate: {fp_rate:.3f} ({fp}/{n_sec})  avg: {avg_ms:.0f} ms/proj{extra}")
    return det_rate, fp_rate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-kics", action="store_true")
    ap.add_argument("--skip-checkov", action="store_true")
    ap.add_argument("--aegis-only", action="store_true")
    args = ap.parse_args()

    dev_manifest = json.load(open(os.path.join(HERE, "manifest.json")))
    ho_manifest = json.load(open(os.path.join(HERE, "heldout", "manifest.json")))

    splits = [("dev", os.path.join(HERE, "projects"), dev_manifest),
              ("held-out", os.path.join(HERE, "heldout", "projects"), ho_manifest)]

    aegis_scores = {}
    for name, proj_dir, manifest in splits:
        print(f"scanning {name} with Aegis ({len(manifest)} projects)...", flush=True)
        results, errors = scan_aegis_split(name, proj_dir, manifest)
        if errors:
            print(f"  SCAN ERRORS: {errors}")
        s = score_aegis(name, manifest, results)
        aegis_scores[name] = s
        print_aegis_report(s)

    gate_ok = True
    ho_f1 = aegis_scores["held-out"]["f1"]
    print(f"\nHELD-OUT F1 GATE (>= {HELDOUT_F1_GATE:.2f}): {ho_f1:.3f} -> "
          f"{'PASS' if ho_f1 >= HELDOUT_F1_GATE else 'FAIL'}")
    if ho_f1 < HELDOUT_F1_GATE:
        gate_ok = False

    if not args.aegis_only:
        print("\n===== COMPARISON (context) =====")
        print("KICS: medium+ = HIGH/MEDIUM. Checkov: severity null in JSON -> all failed checks count.")
        for name, proj_dir, manifest in splits:
            print(f"\n--- {name} ({len(manifest)} projects) ---")
            tmp = os.path.join(HERE, ".tmpcmp", name)
            if not args.skip_checkov and os.path.exists(CHECKOV):
                try:
                    per_proj, ms = run_checkov_bulk(proj_dir, os.path.join(tmp, "ck"))
                    comparison_report(name, manifest, per_proj, "Checkov", ms)
                except Exception as e:  # noqa: BLE001
                    print(f"  Checkov: FAILED ({e})")
            if not args.skip_kics and os.path.exists(KICS):
                try:
                    per_proj, ms, nfail = run_kics_bulk(proj_dir, os.path.join(tmp, "kics"))
                    comparison_report(name, manifest, per_proj, "KICS", ms,
                                      extra=f"  files_failed_to_scan={nfail}")
                except Exception as e:  # noqa: BLE001
                    print(f"  KICS: FAILED ({e})")

    print("\nDONE")
    sys.exit(0 if gate_ok else 1)


if __name__ == "__main__":
    main()
