#!/usr/bin/env python3
"""Record baseline expectations for parity fixtures.

Walks benchmark/parity/fixtures/<control>/<variant>/<format>/, runs
`aegis scan --format=json` on each fixture dir, and writes expect.json
with normalized findings.

Normalized finding: (rule_id, severity, resource_type) — resource NAME
is stripped for cross-format comparison; counts are preserved.

Usage: python3 benchmark/parity/record.py [--aegis /path/to/aegis]
"""
import json, os, subprocess, sys, hashlib, collections

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
AEGIS = "/tmp/aegis-parity"
for a in sys.argv[1:]:
    if a.startswith("--aegis="):
        AEGIS = a.split("=", 1)[1]

def scan(d):
    p = subprocess.run([AEGIS, "scan", "--format=json", d],
                       capture_output=True, text=True, timeout=120)
    if not p.stdout.strip():
        raise RuntimeError(f"empty stdout scanning {d}: stderr={p.stderr[:500]}")
    return json.loads(p.stdout), p.returncode

def normalize(findings):
    out = []
    for f in findings:
        rtype = f["resource"].rsplit(".", 1)[0] if "." in f["resource"] else f["resource"]
        out.append((f["rule_id"], f["severity"], rtype))
    return sorted(out)

def main():
    recorded, errors = 0, 0
    for control in sorted(os.listdir(ROOT)):
        cdir = os.path.join(ROOT, control)
        if not os.path.isdir(cdir):
            continue
        for variant in sorted(os.listdir(cdir)):
            vdir = os.path.join(cdir, variant)
            if not os.path.isdir(vdir):
                continue
            for fmt in sorted(os.listdir(vdir)):
                fdir = os.path.join(vdir, fmt)
                if not os.path.isdir(fdir):
                    continue
                # skip dirs with no input files
                inputs = [x for x in os.listdir(fdir)
                          if not x.startswith("expect") and not x.startswith(".")]
                if not inputs:
                    print(f"SKIP {control}/{variant}/{fmt}: no input files")
                    continue
                try:
                    # 3 runs for determinism hash
                    hashes = set()
                    first = None
                    for _ in range(3):
                        data, code = scan(fdir)
                        norm = normalize(data.get("findings", []))
                        h = hashlib.sha256(json.dumps(norm).encode()).hexdigest()
                        hashes.add(h)
                        if first is None:
                            first = (data, code, norm)
                    data, code, norm = first
                    comp = data.get("scan_completeness", {})
                    counts = collections.Counter(norm)
                    expect = {
                        "control": control,
                        "variant": variant,
                        "format": fmt,
                        "files": sorted(inputs),
                        "exit_code": code,
                        "findings": [
                            {"rule_id": r, "severity": s, "resource_type": t, "count": c}
                            for (r, s, t), c in sorted(counts.items())
                        ],
                        "finding_total": len(norm),
                        "diagnostics": len(data.get("diagnostics", [])),
                        "deterministic": len(hashes) == 1,
                        "determinism_hash": sorted(hashes)[0] if len(hashes) == 1 else sorted(hashes),
                        "completeness": {
                            "discovered": comp.get("files_discovered"),
                            "parsed": comp.get("files_parsed"),
                            "skipped": comp.get("files_skipped"),
                            "failed": comp.get("files_failed"),
                        },
                    }
                    with open(os.path.join(fdir, "expect.json"), "w") as fh:
                        json.dump(expect, fh, indent=1)
                        fh.write("\n")
                    det = "DET" if len(hashes) == 1 else "NONDET!"
                    print(f"OK {control}/{variant}/{fmt}: {len(norm)} findings, {det}")
                    recorded += 1
                except Exception as e:
                    print(f"ERR {control}/{variant}/{fmt}: {e}")
                    errors += 1
    print(f"\nrecorded={recorded} errors={errors}")

if __name__ == "__main__":
    main()
