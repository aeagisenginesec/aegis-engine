#!/usr/bin/env python3
"""Phase 4 (Accuracy & Ground Truth) scoring for the Aegis Independent Validation Mission.

READ-ONLY on everything: runs /tmp/aegis-p4, saves raw JSON, scores against manifests.
Does NOT modify source, does NOT commit.

Metric definitions (per mission task):
  TP = actual finding (deduplicated by rule_id+resource) whose rule ID + resource
       matches an expected finding.
  FP = actual finding with no matching expected finding.
  FN = expected finding with no matching actual finding.
  precision = TP/(TP+FP); recall = TP/(TP+FN); F1 = 2PR/(P+R).
  Finding-level FP rate = FP/(TP+FP)  (= 1 - precision), plus raw FP counts.
  Project-level false-alarm rate = fraction of secure projects with >=1 medium+ finding.
  Info-severity findings are diagnostics (UNCERTAIN etc.), excluded from actionable
  counts; they are tallied separately. This matches the demo post-fix convention.

Corpora:
  (a) AWS demo corpus  tests/demos/aws-security-demo/  (34 TF vuln/secure pairs +
      8 CFN vuln/secure pairs). Labels cover ONLY the tested condition per fixture.
      -> scenario-level detection rate AND tested-condition finding-level precision/
      recall. All other findings are out-of-scope context, NOT scored (broader
      finding-level labels were never independently enumerated).
  (b) corpus-v2 dev (150) + held-out (50). Expected findings are Aegis-authored
      labels (contaminated by design). Strict finding-level scoring is applied;
      note that labels do not enumerate every semantically-true finding, so
      finding-level precision here is a LOWER BOUND on true precision.

Usage: python3 score_phase4.py
Outputs: docs/audit/raw/phase4/ raw JSONs + summary.json
"""
import concurrent.futures
import hashlib
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))          # docs/audit/raw/phase4
REPO = os.path.abspath(os.path.join(ROOT, "..", "..", "..", ".."))
AEGIS = "/tmp/aegis-p4"
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

DEMO = os.path.join(REPO, "tests", "demos", "aws-security-demo")
CORPUS2 = os.path.join(REPO, "benchmark", "corpus-v2")


def scan_dir(path):
    """Scan a directory, return parsed JSON. Raises on unparsable output."""
    p = subprocess.run([AEGIS, "scan", "--format=json", path],
                       capture_output=True, text=True, timeout=180)
    try:
        return json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"scan failed for {path}: exit={p.returncode} stderr={p.stderr[:400]}")


def file_of(finding):
    return (((finding.get("evidence") or {}).get("span") or {}).get("file")) or ""


def fixture_name(path):
    return os.path.basename(path)


def actual_findings(scan, only_basenames=None):
    """Return deduplicated (rule_id, resource, severity_rank, severity) list,
    excluding info-severity (tallied separately). Dedup key: (rule_id, resource)."""
    seen = {}
    infos = []
    for f in scan.get("findings", []):
        fp = file_of(f)
        if only_basenames and os.path.basename(fp) not in only_basenames:
            continue
        rid = f.get("rule_id", "")
        res = f.get("resource", "")
        sev = str(f.get("severity", "")).lower()
        rank = SEV_RANK.get(sev, 0)
        if sev == "info":
            infos.append((rid, res, fp))
            continue
        key = (rid, res)
        if key not in seen or rank > seen[key][2]:
            seen[key] = (rid, res, rank, sev, fp)
    return list(seen.values()), infos


def res_match(expected_res, actual_res):
    """expected may be a bare type ('aws_s3_bucket') or full name ('aws_s3_bucket.demo')."""
    if expected_res == actual_res:
        return True
    if "." not in expected_res:
        return actual_res == expected_res or actual_res.startswith(expected_res + ".")
    return False


# ---------------------------------------------------------------- AWS demo corpus
def score_demo_corpus():
    manifest = json.load(open(os.path.join(DEMO, "manifest.json")))
    scenarios = {s["id"]: s for s in manifest["scenarios"]}
    cfn_subset = set(manifest["cfn_subset"])
    # Rule-identity aliases: the tested condition is fixed but the detecting rule
    # changed with the D1 fix. Scenario 10's manifest expectation (AEGIS-AWS-102)
    # is satisfied by AEGIS-AWS-666 post-fix (documented in DEMO_POSTFIX_COMPARISON).
    RULE_ALIASES = {"10": {"AEGIS-AWS-666"}}

    def fixtures(d, ext):
        out = []
        for fn in sorted(os.listdir(d)):
            if fn.endswith(ext):
                # fixture id: first two chars, e.g. '01-s3-public-acl.tf'
                out.append((fn[:2], os.path.join(d, fn)))
        return out

    results = {"formats": {}, "out_of_scope_context": {}}

    for fmt, subdir, ext, full_expected in [
        ("terraform", "vulnerable", ".tf", True),
        ("terraform", "secure", ".tf", True),
        ("cloudformation", "cfn-vulnerable", ".yaml", True),
        ("cloudformation", "cfn-secure", ".yaml", True),
    ]:
        d = os.path.join(DEMO, subdir)
        t0 = time.time()
        scan = scan_dir(d)
        ms = (time.time() - t0) * 1000
        json.dump(scan, open(os.path.join(ROOT, f"demo_{subdir}.json"), "w"), indent=1)

        fxs = fixtures(d, ext)
        ids = [fid for fid, _ in fxs if (fmt == "terraform" or fid in cfn_subset)]
        if fmt == "terraform":
            # only scenario ids present in manifest
            ids = [fid for fid in ids if fid in scenarios]

        key = f"{fmt}_{subdir}"
        per = {"fixtures": [], "detected": 0, "total": 0,
               "tp": 0, "fp_tested": 0, "fn": 0,
               "out_of_scope_findings": 0, "info_findings": 0,
               "scan_ms": round(ms, 1), "files": len(fxs)}
        is_vuln = "secure" not in subdir
        for fid, fpath in fxs:
            if fmt == "cloudformation" and fid not in cfn_subset:
                continue
            if fid not in scenarios:
                continue
            per["total"] += 1
            sc = scenarios[fid]
            exp_rule, exp_res = sc["rule"], sc["resource"]
            accepted_rules = {exp_rule} | RULE_ALIASES.get(fid, set())
            founds, infos = actual_findings(scan, only_basenames={fixture_name(fpath)})
            per["info_findings"] += len(infos)
            if is_vuln:
                hit = any(r in accepted_rules and res_match(exp_res, res) for (r, res, rk, sev, fp) in founds)
                uncertain_visible = any(r == exp_rule and res_match(exp_res, res)
                                        for (r, res, ffp) in [(i[0], i[1], i[2]) for i in infos])
                per["detected"] += 1 if hit else 0
                per["tp"] += 1 if hit else 0
                per["fn"] += 0 if hit else 1
                # out-of-scope: any actionable finding other than the tested one
                oos = [x for x in founds if not (x[0] in accepted_rules and res_match(exp_res, x[1]))]
                per["out_of_scope_findings"] += len(oos)
                per["fixtures"].append({"id": fid, "scenario": sc["name"],
                                       "tested_condition": "HIT" if hit else ("UNCERTAIN-VISIBLE" if uncertain_visible else "MISS"),
                                       "detected_via_rule": sorted({x[0] for x in founds if x[0] in accepted_rules and res_match(exp_res, x[1])}) or None,
                                       "actionable_findings": len(founds),
                                       "out_of_scope": len(oos),
                                       "info": len(infos)})
            else:
                # secure: a false flag = the TESTED rule (or its alias) firing on the tested condition's resource type
                flag = [x for x in founds if x[0] in accepted_rules and res_match(exp_res, x[1])]
                per["fp_tested"] += 1 if flag else 0
                oos = [x for x in founds if not (x[0] == exp_rule and res_match(exp_res, x[1]))]
                per["out_of_scope_findings"] += len(oos)
                per["fixtures"].append({"id": fid, "scenario": sc["name"],
                                       "tested_condition_false_flag": bool(flag),
                                       "actionable_findings": len(founds),
                                       "out_of_scope": len(oos),
                                       "info": len(infos)})
        per["detection_rate"] = round(per["detected"] / per["total"], 4) if per["total"] and is_vuln else None
        if is_vuln and (per["tp"] + per["fn"]):
            per["tested_condition_recall"] = round(per["tp"] / (per["tp"] + per["fn"]), 4)
        results["formats"][key] = per

    # tested-condition precision for demo: TP/(TP+FP_tested)
    for key in ["terraform_vulnerable", "cloudformation_cfn-vulnerable"]:
        vuln, sec = results["formats"][key], results["formats"][key.replace("vulnerable", "secure") if "cfn" not in key else key.replace("cfn-vulnerable", "cfn-secure")]
        tp, fp = vuln["tp"], sec["fp_tested"]
        vuln["tested_condition_precision"] = round(tp / (tp + fp), 4) if (tp + fp) else None
    return results


# ---------------------------------------------------------------- corpus-v2
def score_corpus2_split(name, proj_dir, manifest_path):
    manifest = json.load(open(manifest_path))
    by_gid = {e["project"]: e for e in manifest}

    def one(entry):
        gid = entry["project"]
        d = os.path.join(proj_dir, gid)
        scan = scan_dir(d)
        return gid, scan

    results = {}
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futs = {ex.submit(one, e): e for e in manifest}
        for fut in concurrent.futures.as_completed(futs):
            gid, scan = fut.result()
            results[gid] = scan
            json.dump(scan, open(os.path.join(ROOT, f"corpus2_{name}_{gid}.json"), "w"))
    wall_ms = (time.time() - t0) * 1000

    tp = fp = fn = 0
    fp_medplus = 0
    tp_by_actual_sev = {}
    crit_high_exp = crit_high_tp = 0
    fp_projects, fn_projects = [], []
    secure_alarm = 0
    n_vuln = n_secure = 0
    exp_by_sev, tp_by_sev = {}, {}
    sev_mismatch = []
    extra_rules = {}
    extra_medplus = []
    info_total = 0

    for gid, scan in results.items():
        entry = by_gid[gid]
        founds, infos = actual_findings(scan)
        info_total += len(infos)
        expected = entry.get("expected", [])
        exp_set = {(e["rule_id"], e["resource"]) for e in expected}
        exp_lookup = {(e["rule_id"], e["resource"]): str(e.get("severity", "")).lower() for e in expected}
        for e in expected:
            esev = str(e.get("severity", "")).lower()
            exp_by_sev[esev] = exp_by_sev.get(esev, 0) + 1
            if esev in ("critical", "high"):
                crit_high_exp += 1

        # match actual -> expected by rule_id + resource (res_match semantics)
        matched_exp = set()
        for (rid, res, rk, sev, fpath) in founds:
            hit = None
            for (er, eres) in exp_set:
                if er == rid and res_match(eres, res):
                    hit = (er, eres)
                    break
            if hit:
                tp += 1
                tp_by_actual_sev[sev] = tp_by_actual_sev.get(sev, 0) + 1
                matched_exp.add(hit)
                expsev = exp_lookup.get(hit, "")
                tp_by_sev[expsev] = tp_by_sev.get(expsev, 0) + 1
                if sev != expsev:
                    sev_mismatch.append({"project": gid, "rule": rid, "resource": res,
                                         "expected_sev": expsev, "actual_sev": sev})
                if expsev in ("critical", "high"):
                    crit_high_tp += 1
            else:
                fp += 1
                extra_rules[rid] = extra_rules.get(rid, 0) + 1
                fp_projects.append((gid, rid, res, sev))
                if rk >= SEV_RANK["medium"]:
                    fp_medplus += 1
                    extra_medplus.append({"project": gid, "rule": rid,
                                          "resource": res, "severity": sev})
        for e in expected:
            key = (e["rule_id"], e["resource"])
            if key not in matched_exp:
                fn += 1
                fn_projects.append({"project": gid, "rule": e["rule_id"],
                                    "resource": e["resource"],
                                    "severity": str(e.get("severity", "")).lower(),
                                    "issue": e.get("issue", "")})
        if entry["vulnerable"]:
            n_vuln += 1
        else:
            n_secure += 1
            if any(rk >= SEV_RANK["medium"] for (_, _, rk, _, _) in founds):
                secure_alarm += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    ch_recall = crit_high_tp / crit_high_exp if crit_high_exp else 0.0
    fp_rate = fp / (tp + fp) if (tp + fp) else 0.0  # = 1 - precision
    alarm_rate = secure_alarm / n_secure if n_secure else 0.0
    # actionable (medium+) precision: excludes low/info findings from FP pool
    tp_mp = sum(c for s, c in tp_by_actual_sev.items() if SEV_RANK.get(s, 0) >= SEV_RANK["medium"])
    p_mp = tp_mp / (tp_mp + fp_medplus) if (tp_mp + fp_medplus) else 0.0

    return {
        "name": name, "format": "terraform-hcl (only format present in corpus-v2)",
        "n_projects": len(manifest), "n_vuln": n_vuln, "n_secure": n_secure,
        "n_expected_findings": sum(len(e.get("expected", [])) for e in manifest),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "finding_level_fp_rate": round(fp_rate, 4),
        # actionable (medium+) precision: low-severity hygiene findings excluded from FP pool
        "tp_medium_plus": tp_mp, "fp_medium_plus": fp_medplus,
        "actionable_precision_medium_plus": round(p_mp, 4),
        "extra_medium_plus_findings": extra_medplus,
        "critical_high_expected": crit_high_exp, "critical_high_tp": crit_high_tp,
        "critical_high_recall": round(ch_recall, 4),
        "project_false_alarm_rate": round(alarm_rate, 4),
        "secure_projects_with_medium_plus": secure_alarm,
        "expected_by_severity": exp_by_sev,
        "recall_by_expected_severity": {s: round(tp_by_sev.get(s, 0) / c, 4) for s, c in exp_by_sev.items() if c},
        "severity_mismatches": sev_mismatch,
        "info_findings_excluded": info_total,
        "extra_firing_rules_top20": sorted(extra_rules.items(), key=lambda x: -x[1])[:20],
        "fn_projects": fn_projects,
        "wall_ms": round(wall_ms, 1),
    }


def main():
    os.makedirs(ROOT, exist_ok=True)
    summary = {
        "binary": AEGIS,
        "note": "Read-only scoring. Info-severity findings excluded from actionable counts.",
        "aws_demo": score_demo_corpus(),
        "corpus_v2": {
            "contamination": ("corpus-v2 fixtures AND expected labels were authored against "
                              "the Aegis rule set during rule development; held-out labels were "
                              "procedurally locked but not cryptographically; the corpus is "
                              "Aegis-centric by design"),
            "dev": score_corpus2_split("dev",
                                       os.path.join(CORPUS2, "projects"),
                                       os.path.join(CORPUS2, "manifest.json")),
            "heldout": score_corpus2_split("heldout",
                                           os.path.join(CORPUS2, "heldout", "projects"),
                                           os.path.join(CORPUS2, "heldout", "manifest.json")),
        },
    }
    json.dump(summary, open(os.path.join(ROOT, "summary.json"), "w"), indent=1)
    print(json.dumps(summary, indent=1)[:6000])
    print("\n... full summary in", os.path.join(ROOT, "summary.json"))


if __name__ == "__main__":
    main()
