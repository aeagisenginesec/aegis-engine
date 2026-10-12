#!/usr/bin/env python3
"""Score the Phase 4 fresh accuracy probe. Strict finding-level metric, same as
score_phase4.py. Extra findings are listed verbatim for semantic review."""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))          # docs/audit/raw/phase4/probe
AEGIS = "/tmp/aegis-p4"
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def scan_dir(path):
    p = subprocess.run([AEGIS, "scan", "--format=json", path],
                       capture_output=True, text=True, timeout=120)
    return json.loads(p.stdout)


def res_match(expected, actual):
    if expected == actual:
        return True
    if "." not in expected:
        return actual == expected or actual.startswith(expected + ".")
    return False


def main():
    manifest = json.load(open(os.path.join(ROOT, "probe_manifest.json")))["projects"]
    tp = fp = fn = 0
    fp_medplus = 0
    crit_high_exp = crit_high_tp = 0
    secure_alarm = n_secure = 0
    per_project = []
    extras_all = []

    for entry in manifest:
        d = os.path.join(ROOT, entry["project"])
        scan = scan_dir(d)
        json.dump(scan, open(os.path.join(ROOT, f"raw_{entry['project']}.json"), "w"), indent=1)
        founds = []
        infos = 0
        seen = set()
        for f in scan.get("findings", []):
            rid, res = f.get("rule_id", ""), f.get("resource", "")
            sev = str(f.get("severity", "")).lower()
            if sev == "info":
                infos += 1
                continue
            if (rid, res) in seen:
                continue
            seen.add((rid, res))
            founds.append((rid, res, sev, f.get("title", "")))
        expected = entry.get("expected", [])
        exp_set = [(e["rule_id"], e["resource"]) for e in expected]
        for e in expected:
            if e["severity"] in ("critical", "high"):
                crit_high_exp += 1
        matched = set()
        proj_extras = []
        for (rid, res, sev, title) in founds:
            hit = next(((er, eres) for (er, eres) in exp_set
                        if er == rid and res_match(eres, res)), None)
            if hit:
                tp += 1
                matched.add(hit)
                esev = next(e["severity"] for e in expected
                            if e["rule_id"] == hit[0] and res_match(e["resource"], res))
                if esev in ("critical", "high"):
                    crit_high_tp += 1
            else:
                fp += 1
                if SEV_RANK.get(sev, 0) >= SEV_RANK["medium"]:
                    fp_medplus += 1
                proj_extras.append({"rule": rid, "resource": res,
                                    "severity": sev, "title": title})
                extras_all.append((entry["project"], rid, res, sev, title))
        proj_fn = []
        for (er, eres) in exp_set:
            if (er, eres) not in matched:
                fn += 1
                esev = next(e["severity"] for e in expected if e["rule_id"] == er)
                proj_fn.append({"rule": er, "resource": eres, "severity": esev})
        if not entry["vulnerable"]:
            n_secure += 1
            if any(SEV_RANK.get(s, 0) >= SEV_RANK["medium"] for (_, _, s, _) in founds):
                secure_alarm += 1
        per_project.append({"project": entry["project"], "format": entry["format"],
                            "vulnerable": entry["vulnerable"],
                            "n_expected": len(expected), "n_found_actionable": len(founds),
                            "n_info": infos, "extras": proj_extras, "missed": proj_fn,
                            "parse_diagnostics": scan.get("diagnostics", [])})

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    result = {
        "n_projects": len(manifest), "n_secure": n_secure,
        "tp": tp, "fp": fp, "fp_medium_plus": fp_medplus, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4),
        "critical_high_recall": round(crit_high_tp / crit_high_exp, 4) if crit_high_exp else None,
        "critical_high": f"{crit_high_tp}/{crit_high_exp}",
        "project_false_alarm_rate": round(secure_alarm / n_secure, 4) if n_secure else None,
        "secure_alarm_projects": secure_alarm,
        "per_project": per_project,
    }
    json.dump(result, open(os.path.join(ROOT, "probe_results.json"), "w"), indent=1)
    print(json.dumps({k: v for k, v in result.items() if k != "per_project"}, indent=1))
    print("\n=== extras for semantic review ===")
    for p, rid, res, sev, title in extras_all:
        print(f"{p:22} {rid:16} {sev:8} {res:45} {title[:60]}")
    print("\n=== missed ===")
    for pr in per_project:
        for m in pr["missed"]:
            print(pr["project"], m)
    print("\n=== secure projects with findings ===")
    for pr in per_project:
        if not pr["vulnerable"] and (pr["extras"] or pr["n_found_actionable"]):
            print(pr["project"], "actionable:", pr["n_found_actionable"], "info:", pr["n_info"])
            for e in pr["extras"]:
                print("   ", e["rule"], e["severity"], e["resource"], e["title"][:60])


if __name__ == "__main__":
    main()
