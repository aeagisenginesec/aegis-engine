#!/usr/bin/env python3
"""Round-2 FP sampling. See docs/audit/11_EVAL_PROTOCOL.md §7-8.

For each scanner, recompute auto-score unmatched findings (fp_candidates) and
export them for adjudication:
- aegis, checkov (the decision pair for win condition (b)): FULL export — every
  unmatched finding is adjudicated (no sampling noise on the decisive pair).
  Fallback: if either scanner's unmatched count exceeds 1500, switch to a
  seeded stratified sample of 1000 (decision recorded in RUNLOG.md).
- kics, trivy (report-only): seeded stratified sample of 400 each.

Stratification: proportional to per-project unmatched counts (largest
remainder), random.sample within project with seed 20261013.

Outputs (docs/audit/raw/final-eval/labels/):
- fp-candidates-<scanner>.json : every unmatched finding with stable id
- fp-sample-<scanner>.json     : the adjudication worklist (full or sampled)
Adjudicators write back fp-adjudicated-<scanner>.json with verdicts.
"""
import json, os, random
from collections import defaultdict
import score

BASE = os.path.dirname(os.path.abspath(__file__))
LABELS = os.path.join(BASE, 'labels')
SEED = 20261013
FULL = {'aegis', 'checkov'}
SAMPLE_N = {'kics': 400, 'trivy': 400}
FULL_FALLBACK_CAP = 1500
FULL_FALLBACK_N = 1000

def stratified_sample(cands_by_proj, n, rng):
    total = sum(len(v) for v in cands_by_proj.values())
    if total <= n:
        return [c for p in sorted(cands_by_proj) for c in cands_by_proj[p]]
    # largest-remainder proportional allocation
    quotas, rem = {}, []
    for p, v in cands_by_proj.items():
        exact = n * len(v) / total
        quotas[p] = int(exact)
        rem.append((exact - int(exact), p))
    leftover = n - sum(quotas.values())
    for _, p in sorted(rem, reverse=True)[:leftover]:
        quotas[p] += 1
    out = []
    for p in sorted(cands_by_proj):
        k = min(quotas[p], len(cands_by_proj[p]))
        out.extend(rng.sample(cands_by_proj[p], k))
    return out

def main():
    os.makedirs(LABELS, exist_ok=True)
    rng = random.Random(SEED)
    cidx = score.build_concept_index()
    plan = {}
    for name, loader in score.LOADERS.items():
        findings = loader()
        s = score.score_scanner(name, findings, cidx)
        cands = s['fp_candidates']
        for i, c in enumerate(cands):
            c['sample_id'] = f'{name}-{i:05d}'
        json.dump(cands, open(os.path.join(LABELS, f'fp-candidates-{name}.json'), 'w'), indent=1)
        by_proj = defaultdict(list)
        for c in cands:
            by_proj[c['project']].append(c)
        if name in FULL and len(cands) > FULL_FALLBACK_CAP:
            worklist = stratified_sample(by_proj, FULL_FALLBACK_N, rng)
            mode = f'fallback-sample-{FULL_FALLBACK_N}'
        elif name in FULL:
            worklist = cands
            mode = 'full'
        else:
            worklist = stratified_sample(by_proj, SAMPLE_N[name], rng)
            mode = f'sample-{SAMPLE_N[name]}'
        json.dump({'scanner': name, 'mode': mode, 'seed': SEED,
                   'n_candidates': len(cands), 'n_worklist': len(worklist),
                   'findings': worklist},
                  open(os.path.join(LABELS, f'fp-sample-{name}.json'), 'w'), indent=1)
        plan[name] = {'mode': mode, 'candidates': len(cands), 'worklist': len(worklist)}
        print(f"{name}: {len(cands)} unmatched -> {mode} ({len(worklist)} to adjudicate)")
    json.dump(plan, open(os.path.join(LABELS, 'fp-sampling-plan.json'), 'w'), indent=1)

if __name__ == '__main__':
    main()
