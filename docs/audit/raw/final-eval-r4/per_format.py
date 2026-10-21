#!/usr/bin/env python3
"""R4 per-format / per-provider breakdowns + coverage matrix.

Uses score.py auto-scores + fp-adjudicated verdicts (same primary method
as stats.py: TP/FN vs firm concepts; FP = adjudicated FP, or extrapolated
fraction for sampled scanners; HYGIENE excluded).
"""
import json, os
from collections import defaultdict
import score

BASE = os.path.dirname(os.path.abspath(__file__))
LABELS = os.path.join(BASE, 'labels')
MANIFEST = {m['id']: m for m in json.load(open(os.path.join(BASE, 'corpus', 'MANIFEST.json')))}
SCANNERS = ['aegis', 'checkov', 'kics', 'trivy']

# Native format support (disclosed coverage; see protocol §6).
SUPPORTS = {
    'aegis': {'terraform', 'cloudformation', 'arm', 'bicep', 'pulumi',
              'dockerfile', 'compose', 'kubernetes'},
    'checkov': {'terraform', 'cloudformation', 'arm', 'bicep',
                'dockerfile', 'kubernetes'},  # no Pulumi/compose misconfig checks
    'kics': {'terraform', 'cloudformation', 'arm', 'bicep', 'pulumi',
             'dockerfile', 'compose', 'kubernetes'},
    'trivy': {'terraform', 'cloudformation', 'arm',
              'dockerfile', 'kubernetes'},  # no Pulumi/compose/Bicep
}


def main():
    cidx = score.build_concept_index()
    # adjudicated FP fractions
    fp_frac = {}
    fp_full = {}
    for name in SCANNERS:
        recs = json.load(open(os.path.join(LABELS, f'fp-adjudicated-{name}.json')))
        eff = sum(1 for r in recs if r['verdict'] in ('FP', 'TP'))
        nfp = sum(1 for r in recs if r['verdict'] == 'FP')
        fp_frac[name] = nfp / eff if eff else 0.0
        fp_by_proj = defaultdict(int)
        for r in recs:
            if r['verdict'] == 'FP':
                fp_by_proj[r['project']] += 1
        fp_full[name] = fp_by_proj
    out = {'formats': {}, 'providers': {}, 'coverage': {}}
    for name in SCANNERS:
        findings = score.LOADERS[name]()
        s = score.score_scanner(name, findings, cidx)
        tp_proj = defaultdict(int)
        for ci in s['tp_concepts']:
            tp_proj[score.GT[ci]['project']] += 1
        fn_proj = defaultdict(int)
        for c in score.GT:
            fn_proj[c['project']] += 1
        for p, t in tp_proj.items():
            fn_proj[p] -= t
        u_proj = defaultdict(int)
        for f in s['fp_candidates']:
            u_proj[f['project']] += 1
        # per-format
        for fmt in sorted({m['format'] for m in MANIFEST.values()}):
            projs = [p for p, m in MANIFEST.items() if m['format'] == fmt]
            tp = sum(tp_proj[p] for p in projs)
            fn = sum(fn_proj[p] for p in projs)
            if name in ('aegis', 'checkov'):
                fp = sum(fp_full[name][p] for p in projs)
            else:
                fp = fp_frac[name] * sum(u_proj[p] for p in projs)
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
            out['formats'].setdefault(fmt, {})[name] = {
                'tp': tp, 'fn': fn, 'fp': round(fp, 1), 'precision': round(prec, 3),
                'recall': round(rec, 3), 'f1': round(f1, 3),
                'fp_rate': round(fp / (tp + fp), 3) if tp + fp else 0.0,
                'supported': fmt in SUPPORTS[name]}
        # per-provider (cloud field: aws/azure/gcp/multi/none)
        for cloud in sorted({m['cloud'] for m in MANIFEST.values()}):
            projs = [p for p, m in MANIFEST.items() if m['cloud'] == cloud]
            tp = sum(tp_proj[p] for p in projs)
            fn = sum(fn_proj[p] for p in projs)
            if name in ('aegis', 'checkov'):
                fp = sum(fp_full[name][p] for p in projs)
            else:
                fp = fp_frac[name] * sum(u_proj[p] for p in projs)
            prec = tp / (tp + fp) if tp + fp else 0.0
            rec = tp / (tp + fn) if tp + fn else 0.0
            f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
            out['providers'].setdefault(cloud, {})[name] = {
                'tp': tp, 'fn': fn, 'fp': round(fp, 1), 'precision': round(prec, 3),
                'recall': round(rec, 3), 'f1': round(f1, 3),
                'fp_rate': round(fp / (tp + fp), 3) if tp + fp else 0.0}
        # coverage-adjusted: metrics restricted to formats the scanner supports
        projs = [p for p, m in MANIFEST.items() if m['format'] in SUPPORTS[name]]
        tp = sum(tp_proj[p] for p in projs)
        fn = sum(fn_proj[p] for p in projs)
        if name in ('aegis', 'checkov'):
            fp = sum(fp_full[name][p] for p in projs)
        else:
            fp = fp_frac[name] * sum(u_proj[p] for p in projs)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        out['coverage'][name] = {
            'supported_formats': sorted(SUPPORTS[name]),
            'n_supported_projects': len(projs),
            'tp': tp, 'fn': fn, 'fp': round(fp, 1),
            'precision': round(prec, 3), 'recall': round(rec, 3),
            'f1': round(f1, 3),
            'fp_rate': round(fp / (tp + fp), 3) if tp + fp else 0.0}
    json.dump(out, open(os.path.join(BASE, 'scores', 'breakdowns.json'), 'w'), indent=1)
    print(json.dumps(out['coverage'], indent=1))
    print('\nper-format F1 (supported only marked):')
    for fmt, d in out['formats'].items():
        print(f"  {fmt:14}", {s: (d[s]['f1'] if d[s]['supported'] else 'SKIP') for s in SCANNERS})


if __name__ == '__main__':
    main()
