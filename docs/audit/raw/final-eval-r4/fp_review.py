#!/usr/bin/env python3
"""R4 FP-adjudication review helper.

Groups unmatched findings (labels/fp-candidates-<scanner>.json) by rule,
prints up to 3 sample instances per rule with the code context they point
at, so the adjudicator can assign a rule-level verdict (TP / FP / HYGIENE)
with per-rule justification, plus instance-level overrides for
context-sensitive rules.

Usage: python3 fp_review.py <scanner> [rule-substring]
"""
import json, os, re, sys

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'corpus')

def code_context(project, file_hint, n=25):
    pdir = os.path.join(CORPUS, project)
    if not os.path.isdir(pdir):
        return '(no such project dir)'
    # find the file: hint may be a basename or a path fragment
    cands = []
    for fn in sorted(os.listdir(pdir)):
        if fn == 'MANIFEST.json':
            continue
        if file_hint and (fn in file_hint or file_hint in fn):
            cands.append(fn)
    if not cands:
        cands = [fn for fn in sorted(os.listdir(pdir)) if fn != 'MANIFEST.json']
    out = []
    for fn in cands[:1]:
        try:
            lines = open(os.path.join(pdir, fn)).read().split('\n')
        except Exception as e:
            return f'(unreadable {fn}: {e})'
        out.append(f'--- {project}/{fn} ({len(lines)} lines) ---')
        out.extend(lines[:n])
    return '\n'.join(out)

def main():
    scanner = sys.argv[1]
    filt = sys.argv[2] if len(sys.argv) > 2 else ''
    cands = json.load(open(os.path.join(BASE, 'labels', f'fp-candidates-{scanner}.json')))
    print(f'{scanner}: {len(cands)} unmatched findings')
    by_rule = {}
    for c in cands:
        by_rule.setdefault(c.get('rule', '?'), []).append(c)
    for rule in sorted(by_rule):
        if filt and filt not in rule:
            continue
        items = by_rule[rule]
        print(f'\n===== {rule}  n={len(items)} =====')
        titles = {i.get('title', '') for i in items}
        for t in sorted(titles)[:3]:
            print(f'  title: {t}')
        for i in items[:2]:
            print(f'  -- {i["project"]} resource={i.get("resource", "")} file={i.get("file", "")}')
            print('   ' + code_context(i['project'], (i.get('file', '') or '').split('/')[-1]).replace('\n', '\n   ')[:2000])

if __name__ == '__main__':
    main()
