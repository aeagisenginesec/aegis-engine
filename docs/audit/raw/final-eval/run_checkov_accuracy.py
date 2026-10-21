#!/usr/bin/env python3
"""Checkov 3.3.26 accuracy sweep over the blind final-eval corpus (205 projects).

Runs, per project id:
    checkov -d <corpus>/<id> -o json --quiet
and saves stdout verbatim to <out>/<id>.json.

Exit codes: 0 = no failed checks, 1 = failed checks found, 2 = error.
Recorded per-project in <out>/EXITCODES.json (flushed after every project).
On exit 2 / crash / timeout (>300s): stderr tail recorded, retried ONCE;
if still failing, recorded in <out>/FAILURES.json and never written as a
fake zero-finding output.

Resume-safe: ids already present in EXITCODES.json or FAILURES.json are
skipped, so a machine restart loses at most the in-flight project.
"""
import json
import os
import subprocess
import sys
import time

CORPUS = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval/corpus")
OUT = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval/scanner-output/checkov")
CHECKOV = os.path.expanduser("~/workspace/.venv-checkov/bin/checkov")
TIMEOUT = 300  # seconds per project
CMD_TEMPLATE = [CHECKOV, "-d", "<corpus>/<id>", "-o", "json", "--quiet"]


def project_ids():
    ids = []
    for prefix, count in (("t", 70), ("c", 70), ("k", 65)):
        ids.extend(f"{prefix}{i:03d}" for i in range(1, count + 1))
    return ids


def run_once(pid):
    """Returns (code, stdout, stderr). code is int, 'timeout', or 'crash'."""
    pdir = os.path.join(CORPUS, pid)
    try:
        p = subprocess.run(
            [CHECKOV, "-d", pdir, "-o", "json", "--quiet"],
            capture_output=True, timeout=TIMEOUT, text=True, cwd="/tmp",
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        so = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        se = e.stderr.decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
        return "timeout", so, se + f"\n[TIMEOUT after {TIMEOUT}s]"
    except Exception as e:  # noqa: BLE001 - must not lose the project silently
        return "crash", "", f"EXCEPTION: {e!r}"


def is_hard_failure(code):
    return code == 2 or code == "timeout" or code == "crash" or (isinstance(code, int) and code < 0)


def main():
    os.makedirs(OUT, exist_ok=True)
    ec_path = os.path.join(OUT, "EXITCODES.json")
    f_path = os.path.join(OUT, "FAILURES.json")
    meta_path = os.path.join(OUT, "SWEEP_META.json")

    exitcodes = json.load(open(ec_path)) if os.path.exists(ec_path) else {}
    failures = json.load(open(f_path)) if os.path.exists(f_path) else {}

    version_out = subprocess.run([CHECKOV, "--version"], capture_output=True, text=True).stdout.strip()
    if version_out != "3.3.26":
        print(f"REFUSING: checkov version is {version_out!r}, expected 3.3.26", flush=True)
        sys.exit(3)

    done = set(exitcodes) | set(failures)
    todo = [i for i in project_ids() if i not in done]
    start_wall = time.time()
    start_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    print(f"[accuracy] checkov {version_out} | resuming: {len(done)} done, {len(todo)} to run | start {start_iso}", flush=True)

    for n, pid in enumerate(todo, 1):
        code, stdout, stderr = run_once(pid)
        if is_hard_failure(code):
            code2, stdout2, stderr2 = run_once(pid)  # retry exactly once
            attempts = [
                {"code": code, "stderr_tail": stderr[-4000:]},
                {"code": code2, "stderr_tail": stderr2[-4000:]},
            ]
            if is_hard_failure(code2):
                failures[pid] = {"status": "failed", "attempts": attempts}
                json.dump(failures, open(f_path, "w"), indent=1)
                print(f"[{n}/{len(todo)}] {pid}: FAILED ({code} -> {code2})", flush=True)
                continue
            code, stdout, stderr = code2, stdout2, stderr2
        # Success path: stdout must be non-empty valid JSON, else it's a failure too.
        try:
            parsed = json.loads(stdout)
            valid = True
        except Exception as e:  # noqa: BLE001
            valid = False
            failures[pid] = {
                "status": "invalid_or_empty_json_output",
                "exit_code": code,
                "json_error": str(e),
                "stdout_head": stdout[:2000],
                "stderr_tail": stderr[-4000:],
            }
            json.dump(failures, open(f_path, "w"), indent=1)
            print(f"[{n}/{len(todo)}] {pid}: INVALID JSON OUTPUT (exit={code})", flush=True)
            continue
        with open(os.path.join(OUT, pid + ".json"), "w") as f:
            f.write(stdout)
        exitcodes[pid] = code
        json.dump(exitcodes, open(ec_path, "w"), indent=1)
        nchecks = "n/a"
        print(f"[{n}/{len(todo)}] {pid}: exit={code} bytes={len(stdout)}", flush=True)

    end_wall = time.time()
    end_iso = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    meta = {
        "checkov_version": version_out,
        "command": " ".join(CMD_TEMPLATE),
        "timeout_s": TIMEOUT,
        "start_iso": start_iso,
        "end_iso": end_iso,
        "wall_s": round(end_wall - start_wall, 1),
        "ok": len(exitcodes),
        "failed": len(failures),
        "failed_ids": sorted(failures),
    }
    json.dump(meta, open(meta_path, "w"), indent=1)
    print(f"[accuracy] DONE: {meta['ok']} ok, {meta['failed']} failed, wall={meta['wall_s']/60:.1f} min", flush=True)


if __name__ == "__main__":
    main()
