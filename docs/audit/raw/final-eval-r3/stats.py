#!/usr/bin/env python3
"""Round-2 cluster-bootstrap statistics. See docs/audit/12_EVAL_R3_PROTOCOL.md §8.

Sampling unit = project. 10,000 cluster-bootstrap resamples (projects with
replacement). FP counts combine auto-scoring with adjudicated verdicts:
- full adjudication (aegis/checkov): per-project FP counts are exact; only
  project-level resampling contributes variance.
- sampled adjudication (kics/trivy): two-level bootstrap — per resample, redraw
  the FP fraction via Binomial(n, f_hat)/n and apply to unmatched counts.

TP for a scanner = auto TP + adjudicated-TP (labeler-missed genuine issues)
extrapolated the same way as FP. Precision = TP/(TP+FP), recall = TP/(TP+FN),
F1 = 2PR/(P+R), FP rate = FP/(TP+FP), FN rate = FN/(TP+FN).

Decision rules (§8):
- (a) F1: PASS iff every pairwise (Aegis − competitor) F1 95% CI lies
  entirely above 0.
- (b) FP rate: PASS iff the (Checkov − Aegis) FP-rate 95% CI lies entirely
  above 0. Genuine tie iff CI contains 0 AND half-width < 2pp, else
  INCONCLUSIVE.
- (c) Speed: PASS iff Aegis median-of-medians is >2x faster than every
  competitor (KICS: single-run-per-project, documented deviation).

Reads: ground-truth.json, labels/fp-candidates-*.json,
       labels/fp-adjudicated-*.json, scanner-output/*/TIMING.json
Writes: scores/stats.json (+ human-readable summary on stdout)
"""
import json, os, math
import numpy as np
from collections import defaultdict
import score

BASE = os.path.dirname(os.path.abspath(__file__))
LABELS = os.path.join(BASE, 'labels')
SCORES = os.path.join(BASE, 'scores')
RAW = os.path.join(BASE, 'scanner-output')
B = 10000
rng = np.random.default_rng(20261013)
SCANNERS = ['aegis', 'checkov', 'kics', 'trivy']

def load_inputs():
    gt = score.GT
    # Resampling frame = ALL 205 corpus projects (not just those with concepts:
    # concept-less projects still contribute scanner FPs).
    corpus_dir = os.path.join(BASE, 'corpus')
    projects = sorted(d for d in os.listdir(corpus_dir)
                      if d.startswith('r3') and os.path.isdir(os.path.join(corpus_dir, d)))
    # auto scores per scanner
    cidx = score.build_concept_index()
    auto = {}
    for name in SCANNERS:
        findings = score.LOADERS[name]()
        s = score.score_scanner(name, findings, cidx)
        tp_by_proj = defaultdict(int)
        for ci in s['tp_concepts']:
            tp_by_proj[gt[ci]['project']] += 1
        fn_by_proj = defaultdict(int)
        for c in gt:
            fn_by_proj[c['project']] += 1
        for p, t in tp_by_proj.items():
            fn_by_proj[p] -= t
        u_by_proj = defaultdict(int)
        for f in s['fp_candidates']:
            u_by_proj[f['project']] += 1
        auto[name] = {'tp': tp_by_proj, 'fn': fn_by_proj, 'u': u_by_proj,
                      'n_findings': s['n_findings']}
    # adjudicated verdicts per scanner
    adj = {}
    for name in SCANNERS:
        path = os.path.join(LABELS, f'fp-adjudicated-{name}.json')
        recs = json.load(open(path))
        v = defaultdict(int)
        fp_by_proj = defaultdict(int)
        tpmiss_by_proj = defaultdict(int)
        for r in recs:
            v[r['verdict']] += 1
            if r['verdict'] == 'FP':
                fp_by_proj[r['project']] += 1
            elif r['verdict'] == 'TP':
                tpmiss_by_proj[r['project']] += 1
        eff = v['FP'] + v['TP']  # HYGIENE/UNCERTAIN dropped from both num+den
        n_verdicts = sum(1 for r in recs if r['verdict'] in
                         ('FP', 'TP', 'HYGIENE', 'UNCERTAIN'))
        adj[name] = {'fp_by_proj': fp_by_proj, 'tpmiss_by_proj': tpmiss_by_proj,
                     'n_eff': eff, 'n_fp': v['FP'], 'n_tpmiss': v['TP'],
                     'n_hygiene': v['HYGIENE'], 'n_uncertain': v['UNCERTAIN'],
                     'n_verdicts': n_verdicts, 'counts': dict(v)}
    return gt, projects, auto, adj

def project_metrics(name, proj_list, auto, adj, f_fp=None):
    """Aggregate metrics over a (possibly resampled) project list.

    Full adjudication: per-project FP counts are exact.
    Sampled adjudication: pass the (possibly redrawn) FP fraction; it is
    applied to each project's unmatched count.
    TP/FN are always counted against the firm concept universe (protocol §7).
    """
    tp = sum(auto[name]['tp'][p] for p in proj_list)
    fn = sum(auto[name]['fn'][p] for p in proj_list)
    if f_fp is not None:
        u = sum(auto[name]['u'][p] for p in proj_list)
        fp = f_fp * u
    else:
        fp = sum(adj[name]['fp_by_proj'][p] for p in proj_list)
    # PRIMARY (protocol §7, prior-round consistent): TP/FN counted against the
    # 416 firm adjudicated concepts ONLY. Adjudicated TP-missed (labeler-missed
    # genuine issues) are excluded from the FP numerator via f_hat's
    # denominator, but do NOT inflate TP — the concept universe is fixed.
    # (Additive variant reported as sensitivity analysis in the report.)
    tp_tot = tp
    prec = tp_tot / (tp_tot + fp) if (tp_tot + fp) else 0.0
    rec = tp_tot / (tp_tot + fn) if (tp_tot + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fp_rate = fp / (tp_tot + fp) if (tp_tot + fp) else 0.0
    fn_rate = fn / (tp_tot + fn) if (tp_tot + fn) else 0.0
    return {'precision': prec, 'recall': rec, 'f1': f1,
            'fp_rate': fp_rate, 'fn_rate': fn_rate,
            'tp': tp_tot, 'fp': fp, 'fn': fn}

def bootstrap(projects, auto, adj):
    n = len(projects)
    proj_arr = np.array(projects)
    # full adjudication iff every unmatched finding got a verdict
    full = {}
    for s in SCANNERS:
        cands_total = sum(auto[s]['u'].values())
        full[s] = (adj[s]['n_verdicts'] >= cands_total and cands_total > 0)
    print('full-adjudication scanners:', [s for s in SCANNERS if full[s]])
    diffs = {k: [] for k in
             ['f1_aegis-checkov', 'f1_aegis-kics', 'f1_aegis-trivy',
              'fp_checkov-aegis', 'fp_kics-aegis', 'fp_trivy-aegis']}
    # point estimates: sampled scanners use extrapolated fractions
    point = {}
    for s in SCANNERS:
        a = adj[s]
        if full[s]:
            point[s] = project_metrics(s, projects, auto, adj)
        else:
            f_hat = a['n_fp'] / a['n_eff'] if a['n_eff'] else 0.0
            point[s] = project_metrics(s, projects, auto, adj, f_hat)
    # per-scanner metric bootstrap distributions for CIs
    dist = {s: defaultdict(list) for s in SCANNERS}
    for _ in range(B):
        idx = rng.integers(0, n, n)
        pl = proj_arr[idx].tolist()
        m = {}
        for s in SCANNERS:
            a = adj[s]
            # full adjudication (every unmatched finding judged): exact
            # per-project counts, project resampling only. Otherwise sampled:
            # two-level bootstrap with binomial redraw of the FP fraction.
            if full[s]:
                # every unmatched finding adjudicated: exact
                m[s] = project_metrics(s, pl, auto, adj)
            else:
                f_hat = a['n_fp'] / a['n_eff'] if a['n_eff'] else 0.0
                f_star = rng.binomial(a['n_eff'], f_hat) / a['n_eff'] if a['n_eff'] else 0.0
                m[s] = project_metrics(s, pl, auto, adj, f_star)
        diffs['f1_aegis-checkov'].append(m['aegis']['f1'] - m['checkov']['f1'])
        diffs['f1_aegis-kics'].append(m['aegis']['f1'] - m['kics']['f1'])
        diffs['f1_aegis-trivy'].append(m['aegis']['f1'] - m['trivy']['f1'])
        diffs['fp_checkov-aegis'].append(m['checkov']['fp_rate'] - m['aegis']['fp_rate'])
        diffs['fp_kics-aegis'].append(m['kics']['fp_rate'] - m['aegis']['fp_rate'])
        diffs['fp_trivy-aegis'].append(m['trivy']['fp_rate'] - m['aegis']['fp_rate'])
        for s in SCANNERS:
            for k, val in m[s].items():
                if k in ('precision', 'recall', 'f1', 'fp_rate', 'fn_rate'):
                    dist[s][k].append(val)
    out = {'point': point, 'diffs': {}, 'ci': {}}
    for k, vals in diffs.items():
        lo, hi = np.percentile(vals, [2.5, 97.5])
        out['diffs'][k] = {'lo': float(lo), 'hi': float(hi),
                           'mean': float(np.mean(vals))}
    for s in SCANNERS:
        out['ci'][s] = {}
        for k, vals in dist[s].items():
            lo, hi = np.percentile(vals, [2.5, 97.5])
            out['ci'][s][k] = [float(lo), float(hi)]
    return out

def timing_summary():
    t = {}
    for s in SCANNERS:
        p = os.path.join(RAW, s, 'TIMING.json')
        if not os.path.exists(p):
            t[s] = None
            continue
        d = json.load(open(p))
        meds = []
        for pid, rec in d.items():
            if 'warm' in rec and rec['warm']:
                meds.append(float(np.median([rec['cold']] + rec['warm'])))
            elif 'single_run' in rec:
                meds.append(float(rec['single_run']))
            elif 'cold' in rec:
                meds.append(float(rec['cold']))
        t[s] = float(np.median(meds)) if meds else None
    return t

def decide(stats, timing):
    # Round-3 protocol: Aegis wins iff ALL THREE hold vs ALL THREE scanners:
    # (a) highest F1, (b) lowest FP rate, (c) fastest (2x threshold).
    d = stats['diffs']
    a = all(d[k]['lo'] > 0 for k in
            ['f1_aegis-checkov', 'f1_aegis-kics', 'f1_aegis-trivy'])
    # (b): fp_X-aegis CI must be entirely above 0 for X in all three scanners
    b_pairs = ['fp_checkov-aegis', 'fp_kics-aegis', 'fp_trivy-aegis']
    b_pass = all(d[k]['lo'] > 0 for k in b_pairs)
    b_detail = {k: {'lo': d[k]['lo'], 'hi': d[k]['hi']} for k in b_pairs}
    c_ratios = {}
    c = True
    for s in ['checkov', 'kics', 'trivy']:
        if timing.get('aegis') and timing.get(s):
            r = timing[s] / timing['aegis']
            c_ratios[s] = r
            c = c and (r > 2)
        else:
            c_ratios[s] = None
            c = False
    if a and b_pass and c:
        verdict = 'EARNED'
    else:
        verdict = 'NOT YET'
    return {'a_f1': a, 'b_fp_pass': b_pass, 'b_fp_detail': b_detail,
            'c_speed': c, 'c_ratios': c_ratios, 'verdict': verdict}

def main():
    os.makedirs(SCORES, exist_ok=True)
    gt, projects, auto, adj = load_inputs()
    print(f'projects={len(projects)} concepts={len(gt)}')
    for s in SCANNERS:
        a = adj[s]
        print(f"{s}: adjudicated eff={a['n_eff']} "
              f"(FP={a['n_fp']} TP-missed={a['n_tpmiss']} "
              f"hygiene={a['n_hygiene']} uncertain={a['n_uncertain']})")
    stats = bootstrap(projects, auto, adj)
    timing = timing_summary()
    decision = decide(stats, timing)
    json.dump({'stats': stats, 'timing': timing, 'decision': decision,
               'n_projects': len(projects), 'n_concepts': len(gt)},
              open(os.path.join(SCORES, 'stats.json'), 'w'), indent=1)
    print('\n=== per-scanner metrics (point + 95% CI) ===')
    for s in SCANNERS:
        p, ci = stats['point'][s], stats['ci'][s]
        print(f"{s}: F1={p['f1']:.3f} [{ci['f1'][0]:.3f},{ci['f1'][1]:.3f}] "
              f"P={p['precision']:.3f} R={p['recall']:.3f} "
              f"FP={p['fp_rate']:.3f} [{ci['fp_rate'][0]:.3f},{ci['fp_rate'][1]:.3f}] "
              f"FN={p['fn_rate']:.3f}")
    print('\n=== pairwise differences (95% CI) ===')
    for k, v in stats['diffs'].items():
        print(f"{k}: [{v['lo']:+.4f},{v['hi']:+.4f}] mean={v['mean']:+.4f}")
    print('\n=== timing (median of per-project medians, s) ===')
    for s in SCANNERS:
        print(f'{s}: {timing.get(s)}')
    print('\n=== decision ===')
    print(json.dumps(decision, indent=1))

if __name__ == '__main__':
    main()
