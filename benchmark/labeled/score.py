#!/usr/bin/env python3
"""Score the Aegis labeled corpus.

For every project in manifest.json, runs `aegis scan --format=json` and
compares the actual rule_ids against the manifest's expected rule_ids.

Project-level:
  TP = vulnerable project with >=1 expected rule_id found
  FP = secure project with >=1 medium+ finding
  FN = vulnerable project where NONE of the expected rule_ids fired
Prints precision, recall, F1 and false-positive rate separately, plus
per-rule precision and REVIEW flags for rules under 80%.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
AEGIS = os.path.join(os.path.dirname(HERE), "..", "aegis")
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def scan(project_dir):
    p = subprocess.run(
        [AEGIS, "scan", "--format=json", project_dir],
        capture_output=True, text=True, timeout=120)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"scan failed for {project_dir}: exit={p.returncode} stderr={p.stderr[:500]}")


def main():
    manifest = json.load(open(os.path.join(HERE, "manifest.json")))
    aegis_bin = os.path.abspath(AEGIS)
    tp = fp = fn = 0
    n_vuln = n_secure = 0
    per_rule_expected = {}   # rule_id -> times found on a project that expected it
    per_rule_any = {}        # rule_id -> times found on any project
    fn_projects = []
    fp_projects = []
    rule_sev = {}

    for entry in manifest:
        proj = entry["project"]
        d = os.path.join(HERE, "projects", proj)
        result = scan(d)
        found = {}  # rule_id -> max severity rank seen
        for f in result.get("findings", []):
            rid = f.get("rule_id", "")
            sev = str(f.get("severity", "")).lower()
            found[rid] = max(found.get(rid, 0), SEV_RANK.get(sev, 0))
            rule_sev.setdefault(rid, sev)
        expected_ids = {e["rule_id"] for e in entry.get("expected", [])}

        if entry["vulnerable"]:
            n_vuln += 1
            hit = bool(expected_ids & set(found))
            if hit:
                tp += 1
            else:
                fn += 1
                fn_projects.append((proj, sorted(expected_ids), sorted(found)))
        else:
            n_secure += 1
            medium_plus = [r for r, s in found.items() if s >= SEV_RANK["medium"]]
            if medium_plus:
                fp += 1
                fp_projects.append((proj, sorted(medium_plus)))

        for rid in found:
            per_rule_any[rid] = per_rule_any.get(rid, 0) + 1
        for rid in expected_ids & set(found):
            per_rule_expected[rid] = per_rule_expected.get(rid, 0) + 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fp_rate = fp / n_secure if n_secure else 0.0

    print(f"projects: {n_vuln} vulnerable, {n_secure} secure")
    print(f"TP={tp}  FP={fp}  FN={fn}")
    print(f"precision          : {precision:.3f}")
    print(f"recall             : {recall:.3f}")
    print(f"F1                 : {f1:.3f}")
    print(f"false-positive rate: {fp_rate:.3f}  (FP / {n_secure} secure projects)")

    if fn_projects:
        print("\n--- FALSE NEGATIVES (expected rule did not fire) ---")
        for proj, exp, got in fn_projects:
            print(f"  {proj}: expected={exp} got={got}")

    if fp_projects:
        print("\n--- FALSE POSITIVES (secure project with medium+ findings) ---")
        for proj, rules in fp_projects:
            print(f"  {proj}: {rules}")

    print("\n--- PER-RULE PRECISION (found_when_expected / found_at_all) ---")
    print("(only rules that appear in at least one manifest expected list)")
    manifest_rules = {e["rule_id"] for m in manifest for e in m.get("expected", [])}
    review = []
    for rid in sorted(manifest_rules):
        any_n = per_rule_any[rid]
        exp_n = per_rule_expected.get(rid, 0)
        prec = exp_n / any_n
        sev = rule_sev.get(rid, "?")
        flag = "  <-- REVIEW" if prec < 0.8 else ""
        if prec < 0.8:
            review.append((rid, prec, exp_n, any_n))
        print(f"  {rid} [{sev:8s}] {exp_n:3d}/{any_n:3d} = {prec:.3f}{flag}")
    # rules that were expected but never fired at all
    never = sorted({e["rule_id"] for m in manifest for e in m.get("expected", [])} - set(per_rule_any))
    if never:
        print("\n--- EXPECTED RULES THAT NEVER FIRED ---")
        for rid in never:
            print(f"  {rid}")

    if review:
        print("\n--- RULES NEEDING REVIEW (precision < 80%) ---")
        for rid, prec, exp_n, any_n in review:
            print(f"REVIEW: {rid} precision={prec:.3f} ({exp_n}/{any_n})")


if __name__ == "__main__":
    sys.exit(main())
