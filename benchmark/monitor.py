#!/usr/bin/env python3
"""Continuous benchmark monitor: Aegis vs Checkov over time."""
import subprocess, time, json, os
from datetime import datetime

AEGIS = os.path.expanduser("~/workspace/aegis-engine/aegis")
CHECKOV = os.path.expanduser("~/workspace/.venv-checkov/bin/checkov")
CORPUS = os.path.expanduser("~/workspace/small-vuln")
LOG = os.path.expanduser("~/workspace/aegis-engine/benchmark/monitor_log.jsonl")

def scan_aegis():
    s = time.perf_counter()
    r = subprocess.run([AEGIS, "scan", CORPUS, "--format=json"],
                      capture_output=True, text=True, timeout=30)
    ms = (time.perf_counter() - s) * 1000
    findings = len(json.loads(r.stdout).get("findings", []))
    return findings, round(ms, 1)

def scan_checkov():
    s = time.perf_counter()
    r = subprocess.run([CHECKOV, "-d", CORPUS, "--framework", "terraform", "-o", "json"],
                      capture_output=True, text=True, timeout=120)
    ms = (time.perf_counter() - s) * 1000
    failed = json.loads(r.stdout)["summary"]["failed"]
    return failed, round(ms, 1)

a_find, a_ms = scan_aegis()
c_find, c_ms = scan_checkov()

entry = {
    "timestamp": datetime.utcnow().isoformat(),
    "aegis": {"findings": a_find, "ms": a_ms},
    "checkov": {"findings": c_find, "ms": c_ms},
    "speedup": round(c_ms / max(a_ms, 1), 1),
}
with open(LOG, "a") as f:
    f.write(json.dumps(entry) + "\n")
print(f"Logged: Aegis {a_find} findings/{a_ms}ms | Checkov {c_find} findings/{c_ms}ms | {entry['speedup']}x")
