#!/usr/bin/env python3
"""Round-4 scanner sweep for aegis / checkov / trivy.

Accuracy: 1 JSON run per project -> scanner-output/<s>/r4N>.json
Timing: 5 timed runs on the 30-project stratified subset -> TIMING.json
(wall via perf_counter, peak RSS via getrusage children).

Usage: python3 sweep_scanner.py <aegis|checkov|trivy>
"""
import json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from timing_harness import time_project

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'corpus')
SCANNER = sys.argv[1]
OUT = os.path.join(BASE, 'scanner-output', SCANNER)
os.makedirs(OUT, exist_ok=True)
SUBSET = json.load(open(os.path.join(BASE, 'timing-subset.json')))
PROJECTS = sorted(d for d in os.listdir(CORPUS)
                  if d.startswith('r4') and os.path.isdir(os.path.join(CORPUS, d)))

AEGIS = '/tmp/aegis-item1/aegis'
CHECKOV = os.path.expanduser('~/workspace/.venv-checkov/bin/checkov')
TRIVY = os.path.expanduser('~/workspace/bin/trivy')

def accuracy_cmd(pid):
    d = os.path.join(CORPUS, pid)
    if SCANNER == 'aegis':
        return [AEGIS, 'scan', d, '--format=json']
    if SCANNER == 'checkov':
        return [CHECKOV, '-d', d, '-o', 'json', '--quiet']
    if SCANNER == 'trivy':
        return [TRIVY, 'config', '--skip-version-check', '--skip-check-update',
                '--format', 'json', d]
    raise ValueError(SCANNER)

def main():
    runlog = [f'# {SCANNER} round-3 sweep', '']
    t0 = time.time()
    fails = {}
    for pid in PROJECTS:
        outp = os.path.join(OUT, f'{pid}.json')
        if os.path.exists(outp) and os.path.getsize(outp) > 0:
            continue  # resume
        try:
            p = subprocess.run(accuracy_cmd(pid), capture_output=True,
                               timeout=600, text=True)
            open(outp, 'w').write(p.stdout)
            if p.returncode not in (0, 1):
                fails[pid] = f'exit={p.returncode} err={p.stderr[-200:]}'
        except subprocess.TimeoutExpired:
            fails[pid] = 'timeout'
        except Exception as e:
            fails[pid] = f'error: {e}'
    runlog.append(f'accuracy: {len(PROJECTS)} projects, {len(fails)} failures')
    for pid, why in fails.items():
        runlog.append(f'  FAIL {pid}: {why}')
    # timing on subset (5 runs; fresh accuracy-style invocation)
    timing = {}
    for pid in SUBSET:
        d = os.path.join(CORPUS, pid)
        if SCANNER == 'aegis':
            cmd = [AEGIS, 'scan', d, '--format=json']
        elif SCANNER == 'checkov':
            cmd = [CHECKOV, '-d', d, '-o', 'json', '--quiet']
        else:
            cmd = [TRIVY, 'config', '--skip-version-check',
                   '--skip-check-update', '--format', 'json', d]
        timing[pid] = time_project(cmd, runs=5, timeout=900)
    json.dump(timing, open(os.path.join(OUT, 'TIMING.json'), 'w'), indent=1)
    runlog.append(f'timing: {len(SUBSET)} projects x 5 runs')
    runlog.append(f'wall: {time.time()-t0:.1f}s')
    open(os.path.join(OUT, 'RUNLOG.md'), 'w').write('\n'.join(runlog) + '\n')
    print(f'{SCANNER}: accuracy {len(PROJECTS)-len(fails)}/{len(PROJECTS)} ok, '
          f'timing {len(SUBSET)} done in {time.time()-t0:.0f}s')

if __name__ == '__main__':
    main()
