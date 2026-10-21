#!/usr/bin/env python3
"""Round-3 FP adjudication for Checkov (FULL adjudication of unmatched findings).

Check-level verdicts (verified against code samples per check), with
instance-level overrides for context-sensitive S3 PAB checks on
intentionally-public buckets (same standard as Aegis/Trivy adjudications).
"""
import json

CANDS = json.load(open('labels/fp-candidates-checkov.json'))
PUBLIC_ONLY = {'r3042', 'r3054', 'r3055', 'r3058', 'r3067', 'r3068', 'r3069'}
PAB_CHECKS = {'CKV_AWS_53', 'CKV_AWS_54', 'CKV_AWS_55', 'CKV_AWS_56',
              'CKV2_AWS_6', 'CKV_AWS_20'}

HYGIENE = {
    'CKV_AWS_23': 'every SG/rule has a description: documentation hygiene',
    'CKV_AWS_8': 'launch configuration description: documentation hygiene',
    'CKV_DOCKER_2': 'HEALTHCHECK instruction: availability, not security',
    'CKV2_AWS_60': 'copy tags to snapshots: metadata hygiene',
    'CKV2_AWS_62': 'S3 event notifications: observability wiring, not a vulnerability',
    'CKV2_AWS_61': 'S3 lifecycle configuration: cost/ops hygiene',
    'CKV_AWS_144': 'S3 cross-region replication: availability/DR, not a vulnerability',
    'CKV_AWS_126': 'EC2 detailed monitoring: observability, not security',
    'CKV_AWS_135': 'EC2 EBS optimized: performance, not security',
    'CKV_AWS_353': 'RDS Performance Insights: observability, not security',
    'CKV2_AWS_30': 'RDS Postgres query logging: observability',
    'CKV_AWS_129': 'RDS logs: observability',
    'CKV_AWS_118': 'RDS enhanced monitoring: observability',
    'CKV_AWS_226': 'RDS auto minor upgrades: patch ops hygiene',
    'CKV_AWS_157': 'RDS Multi-AZ: availability, not security',
    'CKV_AZURE_206': 'storage replication: availability',
    'CKV_AZURE_33': 'storage logging (queue): observability',
    'CKV_AZURE_36': 'trusted Microsoft services: connectivity convenience',
    'CKV_AZURE_44': 'storage TLS version: genuine? -> TP (see below)',
}
# Note: CKV_AZURE_44 (TLS version) is a real control -> TP, not hygiene.
del HYGIENE['CKV_AZURE_44']

FP_RULES = {
    'CKV_AWS_382': 'unrestricted egress is standard/by-design; not a misconfiguration',
}


def adjudicate(f):
    rule = f['rule']
    if rule in HYGIENE:
        return 'HYGIENE', HYGIENE[rule]
    if rule in FP_RULES:
        return 'FP', FP_RULES[rule]
    if rule in PAB_CHECKS and f['project'] in PUBLIC_ONLY:
        return ('FP', 'bucket intentionally public; public-access-block would break '
                      'the intended public website')
    return 'TP', 'factually correct finding of a real weakness/control'


recs = []
for i, f in enumerate(CANDS):
    v, j = adjudicate(f)
    recs.append({'sample_id': f['sample_id'], 'project': f['project'],
                 'resource': f['resource'], 'rule': f['rule'],
                 'title': f['title'], 'severity': f['severity'],
                 'verdict': v, 'justification': j})
json.dump(recs, open('labels/fp-adjudicated-checkov.json', 'w'), indent=1)
from collections import Counter
print(Counter(r['verdict'] for r in recs))
print('candidates:', len(CANDS))
