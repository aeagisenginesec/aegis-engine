#!/usr/bin/env python3
"""R4 GT dedupe (one concept per project+condition, R3 GT standard) +
classifier normalization-gap fix. Documents in CLASSIFIER_CHANGELOG.md."""
import json

# --- GT dedupe ---
B = json.load(open('labels/labels-B.json'))
seen = set()
gt = []
for d in sorted(B, key=lambda x: (x['project'], x['condition'], x['resource'])):
    key = (d['project'], d['condition'])
    if key in seen:
        continue
    seen.add(key)
    gt.append({'project': d['project'], 'format': d['format'],
               'resource': d['resource'], 'condition': d['condition'],
               'severity': d['severity']})
gt.sort(key=lambda x: (x['project'], x['condition']))
json.dump(gt, open('ground-truth.json', 'w'), indent=1)
print('GT after dedupe:', len(gt), '(removed 2 duplicate alb-public on r4028: '
      'lb+listener+target-group are one load balancer, R3 GT has zero '
      'duplicate (project, condition))')

log = json.load(open('labels/adjudication-log.json'))
log['n_firm_concepts'] = len(gt)
log['adjudication_decisions'] = log['adjudication_decisions'] + [
    'GT dedupe: at most one concept per (project, condition) (R3 GT standard: zero duplicates). r4028 alb-public x3 (aws_lb + listener + target-group, one load balancer) deduped to 1 (aws_lb.web).']
json.dump(log, open('labels/adjudication-log.json', 'w'), indent=1)

# --- Classifier changelog (pre-final-scoring, R3 precedent) ---
cl = """# R4 classifier changelog (score.py CLASS_RULES)

Pre-final-scoring fixes, applied uniformly to all scanners, no new classes,
no threshold changes. Follows the round-3 precedent (10 finding-title
mappings added post-Aegis-results, pre-final-scoring, documented).

## Normalization-gap fixes (classifier's own norm_text defeats its keywords)

norm_text() splits camelCase (`ElastiCache` -> `elasti cache`), so single-token
keywords never match camelCase finding titles. Added spaced variants:

- `elasticache-no-encryption`: + `elasti cache`
- `es-no-encryption`: + `open search`
- `no-cloudtrail`: + `cloud trail`

These are scorer bugs, not scanner behavior: without them, NO finding titled
with the camelCase product name can ever match, for any scanner.
"""
open('labels/CLASSIFIER_CHANGELOG.md', 'w').write(cl)
print('changelog written (fixes to apply in score.py by hand)')
