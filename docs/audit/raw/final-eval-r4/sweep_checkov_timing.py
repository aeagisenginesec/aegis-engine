#!/usr/bin/env python3
"""R4 Checkov timing-only sweep: 30-subset x 5 runs, strictly sequential.

Must run with no other scanner timing in progress (load distortion).
Reuses sweep_scanner.py's accuracy command + timing_harness.time_project.
"""
import json, os, subprocess, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'corpus')
OUT = os.path.join(BASE, 'scanner-output', 'checkov')
sys.path.insert(0, BASE)
from timing_harness import time_project

CHECKOV = os.path.expanduser('~/workspace/.venv-checkov/bin/checkov')
SUBSET = json.load(open(os.path.join(BASE, 'timing-subset.json')))
os.makedirs(OUT, exist_ok=True)

def accuracy_cmd(pid):
    return [CHECKOV, '-d', os.path.join(CORPUS, pid), '-o', 'json', '--quiet']

timing = {}
t0 = time.time()
runlog = []
for pid in SUBSET:
    timing[pid] = time_project(accuracy_cmd(pid), runs=5, timeout=900)
    med = timing[pid].get('median')
    print(f'{pid}: median={med}', flush=True)
json.dump(timing, open(os.path.join(OUT, 'TIMING.json'), 'w'), indent=1)
runlog.append(f'timing: {len(SUBSET)} projects x 5 runs, {time.time() - t0:.0f}s')
open(os.path.join(OUT, 'RUNLOG.md'), 'a').write('\n'.join(runlog) + '\n')
print(f'checkov timing done in {time.time() - t0:.0f}s')
