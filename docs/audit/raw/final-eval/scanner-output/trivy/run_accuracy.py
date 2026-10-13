#!/usr/bin/env python3
"""Accuracy sweep: trivy config 0.74.0 over the blind eval corpus (205 projects).

READ-ONLY on corpus: ~/workspace/aegis-engine/docs/audit/raw/final-eval/corpus/
Writes <id>.json per project into scanner-output/trivy/ + EXITCODES.json (flushed
incrementally every 10 projects) + FAILURES.json + meta.json.

Invocation (verified): trivy config --skip-version-check --skip-check-update
                       --format json --output <out>/<id>.json <corpus>/<id>

Native skips: formats trivy 0.74.0 `config` cannot scan (bicep, pulumi, compose)
return exit 0 with empty Results -> recorded as status "native_skip", NOT failed,
NOT counted as zero findings silently (they are listed in RUNLOG.md).

Failures: nonzero exit or timeout -> stderr saved to <id>.stderr.txt, retried
ONCE, then recorded as failed with stderr tail in FAILURES.json. Never counted
as zero findings.
"""
import json, os, subprocess, sys, time

TRIVY = os.path.expanduser("~/workspace/bin/trivy")
CORPUS = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval/corpus")
OUT = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval/scanner-output/trivy")
TIMEOUT = 300

NATIVE_SKIP_FORMATS = {"bicep", "pulumi", "compose"}


def project_ids():
    ids = [n for n in sorted(os.listdir(CORPUS))
           if os.path.isdir(os.path.join(CORPUS, n)) and not n.startswith("MANIFEST")]
    return ids


def formats():
    m = json.load(open(os.path.join(CORPUS, "MANIFEST.json")))
    return {e["id"]: e["format"] for e in m}


def flush(records):
    tmp = os.path.join(OUT, "EXITCODES.json.tmp")
    with open(tmp, "w") as f:
        json.dump(records, f, indent=2)
    os.replace(tmp, os.path.join(OUT, "EXITCODES.json"))


def run_once(pid):
    target = os.path.join(CORPUS, pid)
    out = os.path.join(OUT, f"{pid}.json")
    cmd = [TRIVY, "config", "--skip-version-check", "--skip-check-update",
           "--format", "json", "--output", out, target]
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired as e:
        err = e.stderr if isinstance(e.stderr, str) else ""
        return {"exit_code": 124, "wall_s": round(time.time() - t0, 2),
                "stderr": f"TIMEOUT after {TIMEOUT}s\n{err}"}
    return {"exit_code": proc.returncode, "wall_s": round(time.time() - t0, 2),
            "stderr": proc.stderr}


def classify(pid, fmt, out):
    """Read trivy output JSON; classify ok / native_skip / unreadable."""
    try:
        with open(out) as f:
            data = json.load(f)
    except Exception as e:
        return {"status": "unreadable", "reason": f"output JSON unreadable: {e}"}
    results = data.get("Results") or []
    n_mis = sum(len(r.get("Misconfigurations") or []) for r in results)
    if not results and fmt in NATIVE_SKIP_FORMATS:
        return {"status": "native_skip", "results": 0, "misconfigurations": 0,
                "reason": f"format '{fmt}' has no native trivy 0.74.0 config scanner; "
                          "exit 0 with empty Results"}
    return {"status": "ok", "results": len(results), "misconfigurations": n_mis}


def scan(pid, fmt):
    out = os.path.join(OUT, f"{pid}.json")
    err_path = os.path.join(OUT, f"{pid}.stderr.txt")
    r = run_once(pid)
    if r["exit_code"] == 0:
        return dict(r, **classify(pid, fmt, out))
    # first failure -> record stderr, retry once
    with open(err_path, "w") as f:
        f.write(r["stderr"])
    r2 = run_once(pid)
    if r2["exit_code"] == 0:
        if os.path.exists(err_path):
            os.remove(err_path)
        rec = classify(pid, fmt, out)
        rec["wall_s"] = round(r["wall_s"] + r2["wall_s"], 2)
        rec["exit_code"] = 0
        rec["note"] = "succeeded on retry after first failure"
        return rec
    with open(err_path, "w") as f:
        f.write(r2["stderr"])
    if os.path.exists(out):
        os.remove(out)
    return {"exit_code": r2["exit_code"], "wall_s": round(r["wall_s"] + r2["wall_s"], 2),
            "status": "failed", "stderr_file": err_path,
            "stderr_tail": r2["stderr"][-2000:],
            "reason": f"trivy exited {r2['exit_code']} twice (timeout)" if r2["exit_code"] == 124
                      else f"trivy exited {r2['exit_code']} twice; see stderr file"}


def main():
    os.makedirs(OUT, exist_ok=True)
    start_ts = time.strftime("%Y-%m-%d %H:%M:%S %z")
    t_start = time.time()
    ids = project_ids()
    fmts = formats()
    print(f"scanning {len(ids)} projects...", flush=True)
    records, failures = {}, {}
    for i, pid in enumerate(ids, 1):
        rec = scan(pid, fmts.get(pid, "?"))
        records[pid] = rec
        if rec["status"] == "failed":
            failures[pid] = {"exit_code": rec["exit_code"], "reason": rec["reason"],
                             "stderr_tail": rec["stderr_tail"]}
        st = rec["status"]
        extra = (f" misconfigs={rec.get('misconfigurations')}" if st == "ok"
                 else f" fmt={fmts.get(pid,'?')} reason={rec.get('reason','')[:70]}")
        print(f"[{i}/{len(ids)}] {pid}: exit={rec['exit_code']} status={st} wall={rec['wall_s']}s{extra}",
              flush=True)
        if i % 10 == 0 or i == len(ids):
            flush(records)
            with open(os.path.join(OUT, "FAILURES.json"), "w") as f:
                json.dump(failures, f, indent=2)
    end_ts = time.strftime("%Y-%m-%d %H:%M:%S %z")
    flush(records)
    with open(os.path.join(OUT, "FAILURES.json"), "w") as f:
        json.dump(failures, f, indent=2)
    with open(os.path.join(OUT, "meta.json"), "w") as f:
        json.dump({"start": start_ts, "end": end_ts,
                   "wall_s": round(time.time() - t_start, 1)}, f, indent=2)
    n_ok = sum(1 for v in records.values() if v["status"] == "ok")
    n_skip = sum(1 for v in records.values() if v["status"] == "native_skip")
    n_fail = sum(1 for v in records.values() if v["status"] == "failed")
    print(f"DONE: {n_ok} ok, {n_skip} native-skip, {n_fail} failed, wall={round(time.time()-t_start,1)}s")


if __name__ == "__main__":
    sys.exit(main())
