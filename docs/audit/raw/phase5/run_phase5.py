#!/usr/bin/env python3
"""Phase 5 competitive benchmark harness (Aegis Independent Competitive Validation Mission).

Runs Aegis, Checkov, KICS, Trivy x 5 timed runs on each frozen corpus,
saves machine-readable JSON per scanner x corpus, computes medians.
READ-ONLY w.r.t. Aegis source: builds the pinned binary, never modifies it.

Usage: python3 run_phase5.py [--only SCANNER] [--only-corpus CORPUS] [--runs N]
"""
import json, os, shutil, statistics, subprocess, sys, time, argparse
from pathlib import Path

HOME = Path.home()
AE = HOME / "workspace" / "aegis-engine"
RAW = AE / "docs" / "audit" / "raw" / "phase5"
RAWDUMP = RAW / "raw_outputs"
AEGIS_BIN = Path("/tmp/aegis-p5")
KICS_HOME = HOME / "workspace" / "kics"
KICS_BIN = HOME / "workspace" / "bin" / "kics"
CHECKOV_BIN = HOME / "workspace" / ".venv-checkov" / "bin" / "checkov"
RUN_TIMEOUT = 600  # >10 min per run -> kill, record TIMEOUT

CORPORA = {
    "terragoat": {
        "root": str(HOME / "workspace" / "terragoat-fresh" / "terraform"),
        "note": "TerraGoat terraform/ only (47 .tf); repo root package.json/js tooling excluded (not IaC)",
    },
    "vuln-200": {
        "root": str(HOME / "workspace" / "terraform" / "vuln-200"),
        "note": "Single 1351-line main.tf, ~200 resources",
    },
    "corpus-v2": {
        "root": str(AE / "benchmark" / "corpus-v2" / "projects"),
        "note": "Dev set only (150 projects, manifest.json). heldout/ excluded per SPLIT.md restriction policy; gen/ is generator code, not IaC. Labels are Aegis-centric: valid for speed/count, NOT accuracy.",
    },
    "aws-demo": {
        "root": str(AE / "tests" / "demos" / "aws-security-demo"),
        "note": "Whole demo dir: 68 .tf (vulnerable/+secure/) + 16 CloudFormation .yaml + manifest.json",
    },
}

def corpus_files(root):
    counts = {}
    for p in Path(root).rglob("*"):
        if p.is_file():
            counts[p.suffix.lower() or "(none)"] = counts.get(p.suffix.lower() or "(none)", 0) + 1
    return counts

def run_cmd(cmd, cwd=None, timeout=RUN_TIMEOUT):
    t0 = time.perf_counter()
    try:
        pr = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        wall = time.perf_counter() - t0
        return {"wall_s": wall, "exit_code": pr.returncode, "stdout": pr.stdout,
                "stderr": pr.stderr, "status": "ok"}
    except subprocess.TimeoutExpired as e:
        wall = time.perf_counter() - t0
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        err = (e.stderr or "") if isinstance(e.stderr, str) else ""
        return {"wall_s": wall, "exit_code": None, "stdout": out, "stderr": err,
                "status": "TIMEOUT"}

# ---------------- parsers ----------------
def parse_aegis(stdout, stderr, dumpdir, run_i):
    d = json.loads(stdout)
    findings = d.get("findings", [])
    rule_ids = sorted({f.get("rule_id") for f in findings})
    return {
        "findings": len(findings),
        "extra": {
            "resources_scanned": d.get("resources_scanned"),
            "distinct_rule_ids_fired": len(rule_ids),
            "diagnostics": d.get("diagnostics", []),
            "scan_completeness": d.get("scan_completeness", {}),
            "aegis_version": d.get("aegis_version"),
        },
    }

def parse_checkov(stdout, stderr, dumpdir, run_i):
    entries = json.loads(stdout)
    if isinstance(entries, dict):
        entries = [entries]
    total_failed, per_type = 0, {}
    for e in entries:
        r = e.get("results", {})
        s = e.get("summary", {})
        f = len(r.get("failed_checks", []))
        total_failed += f
        per_type[e.get("check_type")] = {
            "failed": f, "passed": len(r.get("passed_checks", [])),
            "skipped": len(r.get("skipped_checks", [])),
            "parsing_errors": s.get("parsing_errors"),
            "resource_count": s.get("resource_count"),
            "checkov_version": s.get("checkov_version"),
        }
    return {"findings": total_failed, "extra": {"per_check_type": per_type}}

def parse_kics(stdout, stderr, dumpdir, run_i):
    outdir = dumpdir / f"kics_out_r{run_i}"
    rj = outdir / "results.json"
    if not rj.exists():
        return {"findings": None, "extra": {"error": "results.json missing", "console_tail": stdout[-2000:]}}
    d = json.loads(rj.read_text())
    tot = sum(len(q.get("files", [])) for q in d.get("queries", []))
    return {
        "findings": tot,
        "extra": {
            "files_scanned": d.get("files_scanned"),
            "files_parsed": d.get("files_parsed"),
            "lines_scanned": d.get("lines_scanned"),
            "lines_parsed": d.get("lines_parsed"),
            "files_failed_to_scan": d.get("files_failed_to_scan"),
            "queries_total": d.get("queries_total"),
            "queries_failed_to_execute": d.get("queries_failed_to_execute"),
            "severity_counters": d.get("severity_counters"),
            "total_counter": d.get("total_counter"),
            "kics_version": d.get("kics_version"),
            "console_tail": stdout[-1500:],
        },
    }

def parse_trivy(stdout, stderr, dumpdir, run_i):
    jf = dumpdir / f"trivy_r{run_i}.json"
    d = json.loads(jf.read_text())
    tot, per_type, targets = 0, {}, []
    for r in d.get("Results", []):
        m = r.get("Misconfigurations") or []
        tot += len(m)
        t = r.get("Type")
        per_type[t] = per_type.get(t, 0) + len(m)
        targets.append({"target": r.get("Target"), "type": t, "misconfigs": len(m)})
    return {"findings": tot, "extra": {"per_type": per_type, "targets": targets,
                                       "trivy_version": (d.get("Trivy") or {}).get("Version")}}

SCANNERS = {
    "aegis": {
        "version_cmd": [str(AEGIS_BIN), "--version"],
        "rule_count": 1185,  # verified via `aegis doctor`: "rule registry: 1185 rules loaded"
        "rule_count_src": "aegis doctor (runtime registry)",
        "formats": ["terraform", "cloudformation"],
        "make_cmd": lambda corpus, dumpdir, i: ([str(AEGIS_BIN), "scan", corpus, "--format=json"], None),
        "parse": parse_aegis,
    },
    "checkov": {
        "version_cmd": [str(CHECKOV_BIN), "--version"],
        "rule_count": 1318,  # terraform resource check registrations in resource_registry
        "rule_count_src": "checkov.terraform.checks.resource.registry (resource checks; data/provider/module checks additional)",
        "formats": ["terraform", "secrets"],
        "make_cmd": lambda corpus, dumpdir, i: ([str(CHECKOV_BIN), "-d", corpus, "--output", "json"], None),
        "parse": parse_checkov,
    },
    "kics": {
        "version_cmd": [str(KICS_BIN), "version"],
        "rule_count": 1811,  # metadata.json count under ~/workspace/kics/assets/queries (all platforms)
        "rule_count_src": "bundled query metadata.json count (all platforms); results.json reports queries_total executed per corpus",
        "formats": ["terraform", "cloudformation", "ansible", "dockerfile", "k8s", "+others (auto-detected)"],
        "make_cmd": lambda corpus, dumpdir, i: (
            [str(KICS_BIN), "scan", "-p", corpus, "-o", str(dumpdir / f"kics_out_r{i}"),
             "--report-formats", "json", "--no-progress", "--minimal-ui"], str(KICS_HOME)),
        "parse": parse_kics,
    },
    "trivy": {
        "version_cmd": ["trivy", "--version"],
        "rule_count": None,
        "rule_count_src": "check-bundle policy count not enumerated; distinct check IDs that fired reported per corpus",
        "formats": ["terraform", "cloudformation", "dockerfile", "k8s (auto-detected by config scan)"],
        "make_cmd": lambda corpus, dumpdir, i: (
            ["trivy", "config", "--format", "json", "--output", str(dumpdir / f"trivy_r{i}.json"), corpus], None),
        "parse": parse_trivy,
    },
}

def get_version(sc):
    pr = subprocess.run(SCANNERS[sc]["version_cmd"], capture_output=True, text=True, timeout=120)
    out = (pr.stdout + pr.stderr).strip().splitlines()
    return "; ".join(out[:2]) if out else "unknown"

def trivy_distinct_checks():
    ids = set()
    for jf in RAWDUMP.glob("trivy_vuln-200/trivy_r*.json"):
        try:
            d = json.loads(jf.read_text())
            for r in d.get("Results", []):
                for m in r.get("Misconfigurations") or []:
                    ids.add(m.get("ID"))
        except Exception:
            pass
    return sorted(i for i in ids if i)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default=None)
    ap.add_argument("--only-corpus", default=None)
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    RAWDUMP.mkdir(parents=True, exist_ok=True)

    scanners = [args.only] if args.only else list(SCANNERS.keys())
    corpora = [args.only_corpus] if args.only_corpus else list(CORPORA.keys())

    for sc in scanners:
        version = get_version(sc)
        for corp in corpora:
            root = CORPORA[corp]["root"]
            print(f"[{sc} x {corp}] version={version}", flush=True)
            dumpdir = RAWDUMP / f"{sc}_{corp}"
            dumpdir.mkdir(parents=True, exist_ok=True)
            runs = []
            for i in range(1, args.runs + 1):
                cmd, cwd = SCANNERS[sc]["make_cmd"](root, dumpdir, i)
                if sc == "kics":
                    shutil.rmtree(dumpdir / f"kics_out_r{i}", ignore_errors=True)
                res = run_cmd(cmd, cwd=cwd)
                (dumpdir / f"run{i}.stdout").write_text(res["stdout"][-50000:])
                (dumpdir / f"run{i}.stderr").write_text(res["stderr"][-20000:])
                rec = {"run": i, "wall_s": round(res["wall_s"], 3),
                       "exit_code": res["exit_code"], "status": res["status"],
                       "findings": None, "extra": {}}
                if res["status"] == "ok":
                    try:
                        p = SCANNERS[sc]["parse"](res["stdout"], res["stderr"], dumpdir, i)
                        rec["findings"] = p["findings"]
                        rec["extra"] = p["extra"]
                        if p["findings"] is None:
                            rec["status"] = "INCOMPLETE"
                    except Exception as e:
                        rec["status"] = f"PARSE_ERROR: {type(e).__name__}: {e}"
                print(f"  run {i}: {rec['status']} wall={rec['wall_s']}s findings={rec['findings']} exit={rec['exit_code']}", flush=True)
                runs.append(rec)
            ok_walls = [r["wall_s"] for r in runs if r["status"] == "ok" and r["findings"] is not None]
            doc = {
                "scanner": sc, "version": version,
                "rule_count": SCANNERS[sc]["rule_count"],
                "rule_count_source": SCANNERS[sc]["rule_count_src"],
                "formats_attempted": SCANNERS[sc]["formats"],
                "corpus": corp, "corpus_root": root,
                "corpus_note": CORPORA[corp]["note"],
                "corpus_files": corpus_files(root),
                "command": " ".join(SCANNERS[sc]["make_cmd"](root, dumpdir, 1)[0]),
                "command_cwd": SCANNERS[sc]["make_cmd"](root, dumpdir, 1)[1],
                "runs": runs,
                "median_wall_s": round(statistics.median(ok_walls), 3) if ok_walls else None,
                "machine": {"vcpu": os.cpu_count(), "mem": open("/proc/meminfo").readline().split()[1] + " kB"},
            }
            (RAW / f"{sc}_{corp}.json").write_text(json.dumps(doc, indent=1))
            print(f"[{sc} x {corp}] median={doc['median_wall_s']}s -> {sc}_{corp}.json", flush=True)

    if not args.only and not args.only_corpus:
        with open(RAW / "trivy_distinct_check_ids.txt", "w") as f:
            f.write("\n".join(trivy_distinct_checks()))
    print("DONE")

if __name__ == "__main__":
    main()
