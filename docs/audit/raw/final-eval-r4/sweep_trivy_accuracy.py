#!/usr/bin/env python3
"""R4 Trivy accuracy-only sweep (timing deferred to a sequential phase).

Same command/config as sweep_scanner.py. Timing is run separately AFTER
Checkov timing completes, so timing measurements are never taken under
concurrent scanner load.
"""
import json, os, subprocess, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'corpus')
OUT = os.path.join(BASE, 'scanner-output', 'trivy')
os.makedirs(OUT, exist_ok=True)
TRIVY = os.path.expanduser('~/workspace/bin/trivy')
PROJECTS = sorted(d for d in os.listdir(CORPUS)
                  if d.startswith('r4') and os.path.isdir(os.path.join(CORPUS, d)))
fails = {}
t0 = time.time()
for pid in PROJECTS:
    outp = os.path.join(OUT, f'{pid}.json')
    if os.path.exists(outp) and os.path.getsize(outp) > 0:
        continue
    try:
        p = subprocess.run([TRIVY, 'config', '--skip-version-check',
                            '--skip-check-update', '--format', 'json',
                            os.path.join(CORPUS, pid)],
                           capture_output=True, timeout=600, text=True)
        open(outp, 'w').write(p.stdout)
        if p.returncode not in (0, 1):
            fails[pid] = f'exit={p.returncode} err={p.stderr[-200:]}'
    except subprocess.TimeoutExpired:
        fails[pid] = 'timeout'
    except Exception as e:
        fails[pid] = f'error: {e}'
print(f'trivy accuracy: {len(PROJECTS) - len(fails)}/{len(PROJECTS)} ok, '
      f'{len(fails)} fails, {time.time() - t0:.0f}s')
for pid, why in fails.items():
    print(f'  FAIL {pid}: {why}')
