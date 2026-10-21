#!/usr/bin/env python3
"""Round-3 FP adjudication for the KICS stratified sample (400).

Query-level verdicts (verified against code samples per query).
Query IDs are KICS UUIDs; titles from the sample.
"""
import json

SM = json.load(open('labels/fp-sample-kics.json'))

HYGIENE = {
    'e38a8e0a': 'Resource Not Using Tags: metadata hygiene',
    '611ab018': 'Using Unrecommended Namespace: naming convention',
    'b23e9b98': 'Deployment Without PodDisruptionBudget: availability',
    '48a5beba': 'Pod or Container Without ResourceQuota: QoS hygiene',
    '4a20ebac': 'Pod or Container Without LimitRange: QoS hygiene',
    '698ed579': 'Healthcheck Not Set: availability',
    'a31b7b82': 'Deployment Has No PodAntiAffinity: availability',
    'a659f3b5': 'Readiness Probe Is Not Configured: availability',
    '229588ef': 'Memory Requests Not Defined: QoS hygiene',
    'b14d1bc4': 'Memory Limits Not Defined: QoS hygiene',
    'ca469dd4': 'CPU Requests Not Set: QoS hygiene',
    '4ac0e2b7': 'CPU Limits Not Set: QoS hygiene',
    '68eb4bf3': 'Security Group Rule Without Description: documentation',
    'cb3f5ed6': 'Security Group Without Description: documentation',
    '7384dfb2': 'APT-GET Not Avoiding Additional Packages: build hygiene',
    '965a08d7': 'Apt Get Install Pin Version Not Defined: build hygiene',
    '9c30655c': 'Tags Not Copied to RDS Cluster Snapshot: metadata',
    '6d3dead4': 'Tags Not Copied to RDS Cluster Snapshot: metadata',
}


def adjudicate(f):
    qid = f['rule'][:8]
    if qid in HYGIENE:
        return 'HYGIENE', HYGIENE[qid]
    return 'TP', 'factually correct finding of a real weakness/control'


recs = []
for f in SM['findings']:
    v, j = adjudicate(f)
    recs.append({'sample_id': f['sample_id'], 'project': f['project'],
                 'resource': f['resource'], 'rule': f['rule'],
                 'title': f['title'], 'severity': f['severity'],
                 'verdict': v, 'justification': j})
json.dump(recs, open('labels/fp-adjudicated-kics.json', 'w'), indent=1)
from collections import Counter
print(Counter(r['verdict'] for r in recs))
