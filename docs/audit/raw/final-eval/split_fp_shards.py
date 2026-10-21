#!/usr/bin/env python3
"""Split fp-sample worklists into adjudication shards.

Reads labels/fp-sample-<scanner>.json (written by fp_sample.py) and writes
labels/fp-shards/fp-<scanner>-shard<i>.json with the worklist findings split
round-robin (interleaved by project order, so each shard covers all projects).

Shard plan:
- aegis, checkov (full adjudication): 5 shards each
- kics, trivy (400-samples): 1 shard each (copy of the sample worklist)
Writes labels/fp-shards/_shard-plan.json with the mapping.
"""
import json, os

BASE = os.path.dirname(os.path.abspath(__file__))
LABELS = os.path.join(BASE, 'labels')
SHARDS = os.path.join(LABELS, 'fp-shards')
PLAN = {'aegis': 5, 'checkov': 5, 'kics': 1, 'trivy': 1}

def main():
    os.makedirs(SHARDS, exist_ok=True)
    plan = {}
    for scanner, n in PLAN.items():
        src = json.load(open(os.path.join(LABELS, f'fp-sample-{scanner}.json')))
        findings = src['findings']
        # interleave: sort by project, then deal round-robin for project coverage
        findings = sorted(findings, key=lambda f: (f['project'], f['sample_id']))
        shards = [findings[i::n] for i in range(n)]
        for i, sh in enumerate(shards):
            path = os.path.join(SHARDS, f'fp-{scanner}-shard{i}.json')
            json.dump({'scanner': scanner, 'shard': i, 'n_shards': n,
                       'mode': src['mode'], 'findings': sh},
                      open(path, 'w'), indent=1)
        plan[scanner] = {'mode': src['mode'], 'n_shards': n,
                         'shard_sizes': [len(s) for s in shards],
                         'total': len(findings)}
        print(f"{scanner}: {len(findings)} -> {n} shards {plan[scanner]['shard_sizes']}")
    json.dump(plan, open(os.path.join(SHARDS, '_shard-plan.json'), 'w'), indent=1)

if __name__ == '__main__':
    main()
