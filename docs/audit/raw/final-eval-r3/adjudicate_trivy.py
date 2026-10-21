#!/usr/bin/env python3
"""Round-3 FP adjudication for the Trivy stratified sample (400).

Rule-level verdicts (verified against code samples per rule), with
instance-level overrides for context-sensitive S3 PAB checks on
intentionally-public buckets (same standard as the Aegis adjudication).
"""
import json

SM = json.load(open('labels/fp-sample-trivy.json'))
PUBLIC_ONLY = {'r3042', 'r3054', 'r3055', 'r3058', 'r3067', 'r3068', 'r3069'}
PAB_CHECKS = {'AWS-0086', 'AWS-0087', 'AWS-0091', 'AWS-0093', 'AWS-0094'}

HYGIENE = {
    'KSV-0110': 'default namespace: naming/organization, not a vulnerability',
    'KSV-0011': 'CPU not limited: QoS hygiene (consistent with pre-registered K8s hygiene)',
    'KSV-0015': 'CPU requests: QoS hygiene',
    'KSV-0016': 'memory requests: QoS hygiene',
    'KSV-0018': 'memory not limited: QoS hygiene',
    'AWS-0133': 'RDS Performance Insights: observability feature, not security',
    'AWS-0124': 'SG rule description missing: documentation hygiene',
    'AWS-0099': 'SG description missing: documentation hygiene',
    'AZU-0058': 'geo-redundant replication: availability, not security',
    'GCP-0051': 'GKE labels: metadata hygiene',
    'DS-0026': 'no HEALTHCHECK: availability, not security',
    'DS-0029': 'apt-get --no-install-recommends: build hygiene',
}
FP_RULES = {
    'AWS-0104': 'unrestricted egress is standard/by-design; not a misconfiguration',
}


def adjudicate(f):
    rule = f['rule']
    if rule in HYGIENE:
        return 'HYGIENE', HYGIENE[rule]
    if rule in FP_RULES:
        return 'FP', FP_RULES[rule]
    if rule in PAB_CHECKS and f['project'] in PUBLIC_ONLY:
        return ('FP', 'bucket intentionally public; public-access-block would break '
                      'the intended public website (same standard as Aegis AWS-206)')
    return 'TP', 'factually correct finding of a real weakness/control'


recs = []
for f in SM['findings']:
    v, j = adjudicate(f)
    recs.append({'sample_id': f['sample_id'], 'project': f['project'],
                 'resource': f['resource'], 'rule': f['rule'],
                 'title': f['title'], 'severity': f['severity'],
                 'verdict': v, 'justification': j})
json.dump(recs, open('labels/fp-adjudicated-trivy.json', 'w'), indent=1)
from collections import Counter
print(Counter(r['verdict'] for r in recs))
