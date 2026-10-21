#!/usr/bin/env python3
"""Round-3 KICS sweep (batched). KICS 2.1.20 must run with cwd=~/workspace/kics
and --queries-path ./assets/queries.

Accuracy: ONE run over the whole corpus dir -> scanner-output/kics/results.json
  (findings attributed per project via the corpus/<id>/ path segment).
Timing: single timed run per project on the 30-project subset (documented
  deviation, same as round 2) -> TIMING.json {pid: {single_run,...}}.
"""
import json, os, shutil, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from timing_harness import time_project

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'corpus')
OUT = os.path.join(BASE, 'scanner-output', 'kics')
SCRATCH = '/tmp/kics-r3-scratch'
KICS = os.path.expanduser('~/workspace/bin/kics')
KICS_CWD = os.path.expanduser('~/workspace/kics')
os.makedirs(OUT, exist_ok=True)
os.makedirs(SCRATCH, exist_ok=True)
SUBSET = json.load(open(os.path.join(BASE, 'timing-subset.json')))

def main():
    t0 = time.time()
    # accuracy: single full-corpus run
    acc_out = os.path.join(OUT, 'results.json')
    if not (os.path.exists(acc_out) and os.path.getsize(acc_out) > 0):
        odir = os.path.join(SCRATCH, 'full')
        shutil.rmtree(odir, ignore_errors=True)
        p = subprocess.run(
            [KICS, 'scan', '-p', CORPUS, '-o', odir,
             '--report-formats', 'json', '--queries-path', './assets/queries',
             '--ignore-on-exit', 'results', '--no-progress'],
            cwd=KICS_CWD, capture_output=True, text=True, timeout=3600)
        rj = os.path.join(odir, 'results.json')
        if os.path.exists(rj):
            shutil.move(rj, acc_out)
            print(f'kics accuracy: full-corpus run ok ({time.time()-t0:.0f}s)',
                  flush=True)
        else:
            print(f'kics accuracy FAILED exit={p.returncode}: {p.stderr[-300:]}')
            return
    else:
        print('kics accuracy: reusing existing results.json')
    # compatibility: also write per-project symlinks? No — loader reads
    # results.json directly (see score.load_kics: *-results.json glob).
    os.rename(acc_out, os.path.join(OUT, 'full-results.json'))
    # timing: single run per subset project
    timing = {}
    for pid in SUBSET:
        tp = os.path.join(OUT, 'TIMING.json')
        if os.path.exists(tp):
            timing = json.load(open(tp))
            if pid in timing:
                continue
        odir = os.path.join(SCRATCH, f'timing-{pid}')
        shutil.rmtree(odir, ignore_errors=True)
        cmd = [KICS, 'scan', '-p', os.path.join(CORPUS, pid), '-o', odir,
               '--report-formats', 'json', '--queries-path', './assets/queries',
               '--ignore-on-exit', 'results', '--no-progress']
        timing[pid] = time_project(cmd, cwd=KICS_CWD, runs=1, timeout=900)
        json.dump(timing, open(tp, 'w'), indent=1)
        print(f'kics timing {pid}: {timing[pid]["single_run"]:.1f}s', flush=True)
    open(os.path.join(OUT, 'RUNLOG.md'), 'w').write(
        f'# kics round-3 sweep (batched)\n\nwall: {time.time()-t0:.1f}s\n')
    print(f'kics done, total wall {time.time()-t0:.0f}s')

if __name__ == '__main__':
    main()
