#!/usr/bin/env python3
"""R4 Checkov accuracy sweep, sharded.

Checkov startup dominates (~25s/project, mostly idle-wait under VM
contention). Accuracy runs are independent, so they are sharded across
N workers; each worker handles projects[i::N]. Identical command and
config to sweep_scanner.py (protocol-compliant: same per-project runs,
same output files). Timing is NOT done here (timing must be sequential
to avoid load distortion) - see sweep_checkov_timing.py.
Usage: python3 sweep_checkov_slice.py <shard> <nshards>
"""
import json, os, subprocess, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'corpus')
OUT = os.path.join(BASE, 'scanner-output', 'checkov')
os.makedirs(OUT, exist_ok=True)
CHECKOV = os.path.expanduser('~/workspace/.venv-checkov/bin/checkov')
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
        p = subprocess.run([CHECKOV, '-d', os.path.join(CORPUS, pid),
                            '-o', 'json', '--quiet'],
                           capture_output=True, timeout=600, text=True)
        open(outp, 'w').write(p.stdout)
        if p.returncode not in (0, 1):
            fails[pid] = f'exit={p.returncode} err={p.stderr[-200:]}'
    except subprocess.TimeoutExpired:
        fails[pid] = 'timeout'
    except Exception as e:
        fails[pid] = f'error: {e}'
print(f'shard {shard}/{nshards}: {len(mine) - len(fails)}/{len(mine)} ok, '
      f'{len(fails)} fails, {time.time() - t0:.0f}s')
for pid, why in fails.items():
    print(f'  FAIL {pid}: {why}')
