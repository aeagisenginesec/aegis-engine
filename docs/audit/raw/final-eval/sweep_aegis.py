#!/usr/bin/env python3
"""Aegis accuracy + timing sweep (run by coordinator directly)."""
import json, os, subprocess, sys, time

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'corpus')
OUT = os.path.join(BASE, 'scanner-output', 'aegis')
BIN = os.path.join(BASE, 'aegis-frozen')
sys.path.insert(0, BASE)
from timing_harness import time_project

os.makedirs(OUT, exist_ok=True)
ids = sorted(d for d in os.listdir(CORPUS)
             if d[0] in 'tck' and os.path.isdir(os.path.join(CORPUS, d)))
exitcodes, failures = {}, {}
t0 = time.time()
for pid in ids:
    outp = os.path.join(OUT, f'{pid}.json')
    try:
        p = subprocess.run([BIN, 'scan', os.path.join(CORPUS, pid),
                            '--format', 'json'],
                           capture_output=True, timeout=120)
        exitcodes[pid] = p.returncode
        if p.returncode == 137:
            failures[pid] = 'OOM-killed (exit 137)'
            open(outp, 'w').write('')
        else:
            open(outp, 'wb').write(p.stdout)
            try:
                json.loads(p.stdout)
            except Exception as e:
                failures[pid] = f'bad json: {e}'
    except subprocess.TimeoutExpired:
        exitcodes[pid] = 'timeout'
        failures[pid] = 'timeout after 120s'
    print(f'{pid}: exit={exitcodes[pid]}', flush=True)
json.dump(exitcodes, open(os.path.join(OUT, 'EXITCODES.json'), 'w'), indent=1)
json.dump(failures, open(os.path.join(OUT, 'FAILURES.json'), 'w'), indent=1)
print(f'accuracy done: {len(ids)} projects in {time.time()-t0:.1f}s, '
      f'failures={len(failures)}')

# timing: 30-project subset, 5 runs each
subset = json.load(open(os.path.join(BASE, 'timing-subset.json')))
timing = {}
for pid in subset:
    rec = time_project([BIN, 'scan', os.path.join(CORPUS, pid),
                        '--format', 'json'], runs=5, timeout=120)
    timing[pid] = rec
    print(f'{pid}: cold={rec["cold"]*1000:.1f}ms rss={rec["peak_rss_kb"]/1024:.1f}MB',
          flush=True)
json.dump(timing, open(os.path.join(OUT, 'TIMING.json'), 'w'), indent=1)
print('timing done')
