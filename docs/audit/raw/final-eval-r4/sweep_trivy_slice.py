#!/usr/bin/env python3
"""R4 Trivy accuracy-only sweep, sharded (same rationale as checkov shards).
Usage: python3 sweep_trivy_slice.py <shard> <nshards>
"""
import os, subprocess, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'corpus')
OUT = os.path.join(BASE, 'scanner-output', 'trivy')
os.makedirs(OUT, exist_ok=True)
TRIVY = os.path.expanduser('~/workspace/bin/trivy')
shard, nshards = int(sys.argv[1]), int(sys.argv[2])
PROJECTS = sorted(d for d in os.listdir(CORPUS)
                  if d.startswith('r4') and os.path.isdir(os.path.join(CORPUS, d)))
mine = PROJECTS[shard::nshards]
fails = {}
t0 = time.time()
for pid in mine:
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
print(f'trivy shard {shard}/{nshards}: {len(mine) - len(fails)}/{len(mine)} ok, '
      f'{len(fails)} fails, {time.time() - t0:.0f}s')
for pid, why in fails.items():
    print(f'  FAIL {pid}: {why}')
