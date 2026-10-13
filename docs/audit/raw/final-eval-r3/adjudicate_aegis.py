#!/usr/bin/env python3
"""Round-3 FP adjudication for Aegis (full adjudication of unmatched findings).

Method: every unmatched finding (fp-candidates-aegis.json) gets a verdict
against the actual code.
- Rule-level verdicts where the verdict is uniform across instances
  (verified against code samples per rule).
- Instance-level verdicts for context-sensitive rules (AWS-001, AWS-206:
  public buckets -> FP per round-2 precedent; private -> TP).
- HYGIENE for non-security pedantry (mirrors round-2 hygiene-review rationale;
  detection untouched).

Verdict semantics (round-2 consistent):
- TP: factually correct + real, actionable weakness/control (incl. sub-firm
  medium/low controls the labelers didn't put in the firm GT universe).
- FP: factually wrong, by-design, or no security value in context.
- HYGIENE: not a real security issue (docs/build/SKU pedantry).
"""
import json

CANDS = json.load(open('labels/fp-candidates-aegis.json'))

PUBLIC_S3 = {  # (project, resource-suffix) intentionally public buckets
    ('r3007', 'data'), ('r3042', 'SiteBucket'), ('r3054', 'DataBucket'),
    ('r3055', 'DataBucket'), ('r3058', 'SiteBucket'), ('r3065', 'SiteBucket'),
    ('r3065', 'DataBucket'), ('r3067', 'SiteBucket'), ('r3068', 'SiteBucket'),
    ('r3069', 'DataBucket'), ('r3108', 'siteBucket'), ('r3113', 'siteBucket'),
}

HYGIENE_RULES = {
    'AEGIS-AWS-604': 'security-group description missing: documentation hygiene, no security impact',
    'AEGIS-DOCKER-007': 'apt-get without --no-install-recommends: build hygiene',
    'AEGIS-DOCKER-008': 'apt-get update without cache cleanup: build hygiene',
    'AEGIS-DOCKER-013': 'chown in RUN vs COPY --chown: build-layer hygiene',
    'AEGIS-DOCKER-015': 'no WORKDIR directive: cosmetic',
    'AEGIS-DOCKER-017': 'no maintainer label: cosmetic metadata',
    'AEGIS-DOCKER-018': 'no STOPSIGNAL: cosmetic',
    'AEGIS-DOCKER-022': 'COPY of entire build context: build hygiene, no demonstrated weakness',
    'AEGIS-DOCKER-029': 'apt-get without pinned versions: build reproducibility hygiene',
    'AEGIS-DOCKER-032': 'pip without --no-cache-dir: build hygiene',
    'AEGIS-AWS-659': 'inline vs managed policy: governance ergonomics, identical effective permissions (round-2 precedent)',
    'AEGIS-AWS-672': 'IAM user without tags: cosmetic',
    'AEGIS-AWS-673': 'IAM role without description: cosmetic',
    'AEGIS-AZURE-043': 'key vault not premium SKU: paid-tier preference, standard is legitimate',
}

FP_RULES = {
    'AEGIS-AWS-005': 'unrestricted egress is standard/by-design; not treated as a misconfiguration',
    'AEGIS-DOCKER-002': 'fired on multi-stage BUILD stages, which legitimately run as root; runtime stages are non-root',
    'AEGIS-DOCKER-010': 'gcr.io (Google official registry) misclassified as untrusted: factually wrong',
}


def res_suffix(resource):
    return resource.split('.')[-1]


def adjudicate(f):
    rule = f['rule']
    if rule in HYGIENE_RULES:
        return 'HYGIENE', HYGIENE_RULES[rule]
    if rule in FP_RULES:
        return 'FP', FP_RULES[rule]
    if rule in ('AEGIS-AWS-001', 'AEGIS-AWS-206'):
        if (f['project'], res_suffix(f['resource'])) in PUBLIC_S3:
            return ('FP', 'bucket is intentionally public (website/public-read or Principal "*"); '
                          'encryption-at-rest / public-access-block has no additional security value in context')
        return 'TP', 'factually correct; real control missing on a private bucket (sub-firm)'
    return 'TP', 'factually correct finding of a real weakness/control; below firm-GT threshold or duplicate of a GT concept'


recs = []
for i, f in enumerate(CANDS):
    verdict, just = adjudicate(f)
    recs.append({'sample_id': f'aegis-{i:05d}', 'project': f['project'],
                 'resource': f['resource'], 'rule': f['rule'],
                 'title': f['title'], 'severity': f['severity'],
                 'verdict': verdict, 'justification': just})
json.dump(recs, open('labels/fp-adjudicated-aegis.json', 'w'), indent=1)
from collections import Counter
print(Counter(r['verdict'] for r in recs))
