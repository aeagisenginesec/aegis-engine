#!/usr/bin/env python3
"""R4 FP adjudication for the KICS stratified sample (400).

Query-level verdicts (verified against R4 code samples per query).
Query IDs are KICS UUIDs; rule field holds the full UUID.

HYGIENE = R3's KICS table + 2 same-standard additions:
- Trusted Microsoft Services (e25b56cd/5400f379): Checkov CKV_AZURE_36
  (same check) is HYGIENE in R3 ("connectivity convenience").
- Chown Flag Exists (aa93e17f): Aegis DOCKER-013 (same check) is HYGIENE
  in R3 (build-layer hygiene).
All other R4 queries default TP (factually correct + real control),
including logging/monitoring/availability queries — R3's KICS table did
not list them as hygiene, and the scanner-specific R3 tables are kept
as-is for reproducibility (note: R3's Checkov table treats some of those
as hygiene; the asymmetry is inherited, and both verdicts exclude the
finding from the FP numerator, so the comparison is unaffected).
Verified: Generic Password (487f4be7) flags real hardcoded DB password
literals (e.g. MasterUserPassword: Str0ng-...) -> TP.
"""
import json
from collections import Counter

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
    # R4 additions (same standard, direct analogs in R3 tables)
    'e25b56cd': 'Trusted Microsoft Services Not Enabled: connectivity convenience (CKV_AZURE_36 HYGIENE in R3)',
    '5400f379': 'Trusted Microsoft Services Not Enabled: connectivity convenience (CKV_AZURE_36 HYGIENE in R3)',
    'aa93e17f': 'Chown Flag Exists: build-layer hygiene (Aegis DOCKER-013 HYGIENE in R3)',
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
print(Counter(r['verdict'] for r in recs))
print('sample:', len(SM['findings']), 'from', SM['n_candidates'])
