#!/usr/bin/env python3
"""R4 FP adjudication for Checkov (FULL adjudication of unmatched findings).

Check-level verdicts (verified against R4 code samples per check), with
instance-level overrides for public-access-block family checks on
intentionally-public buckets (same standard as R3).

Corrections vs R3's adjudication:
- CKV_AWS_8 is NOT hygiene in R4: it is the EBS-encryption check on EC2
  instances (R3's justification "launch configuration description"
  mischaracterized the check). R4 instances fire on EC2 instances with no
  EBS encryption -> TP.
- CKV_GCP_114 added to the public-only FP set (same PAB logic: enforcing
  public-access prevention on an intentionally-public bucket would break
  the intended design). New in R4 (Checkov did not flag it in R3).
- CKV2_AWS_5 (SG not attached) added as HYGIENE: standalone SG fixtures;
  an unattached SG is dead code, not a vulnerability.
"""
import json
from collections import Counter

CANDS = json.load(open('labels/fp-candidates-checkov.json'))
# Projects whose S3 buckets are intentionally public (GT s3-public-acl/policy)
PUBLIC_ONLY_S3 = {'r4026', 'r4028', 'r4037', 'r4050', 'r4111'}
# Projects whose GCS bucket is intentionally public (GT gcs-public)
PUBLIC_ONLY_GCS = {'r4008'}
PAB_CHECKS = {'CKV_AWS_53', 'CKV_AWS_54', 'CKV_AWS_55', 'CKV_AWS_56',
              'CKV2_AWS_6', 'CKV_AWS_20'}

HYGIENE = {
    # R3 table, inherited (same rationale, re-verified on R4 samples)
    'CKV_AWS_23': 'every SG/rule has a description: documentation hygiene',
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
    # R4 addition
    'CKV2_AWS_5': 'SG not attached to a resource: dead code in standalone-SG fixtures, not a vulnerability',
}

FP_RULES = {
    'CKV_AWS_382': 'unrestricted egress is standard/by-design; not a misconfiguration',
}


def adjudicate(f):
    rule = f['rule']
    if rule in HYGIENE:
        return 'HYGIENE', HYGIENE[rule]
    if rule in FP_RULES:
        return 'FP', FP_RULES[rule]
    if rule in PAB_CHECKS and f['project'] in PUBLIC_ONLY_S3:
        return ('FP', 'bucket intentionally public; public-access-block would break '
                      'the intended public website')
    if rule == 'CKV_GCP_114' and f['project'] in PUBLIC_ONLY_GCS:
        return ('FP', 'bucket intentionally public; public-access prevention would '
                      'break the intended public website')
    return 'TP', 'factually correct finding of a real weakness/control'


recs = []
for f in CANDS:
    v, j = adjudicate(f)
    recs.append({'sample_id': f['sample_id'], 'project': f['project'],
                 'resource': f['resource'], 'rule': f['rule'],
                 'title': f['title'], 'severity': f['severity'],
                 'verdict': v, 'justification': j})
json.dump(recs, open('labels/fp-adjudicated-checkov.json', 'w'), indent=1)
print(Counter(r['verdict'] for r in recs))
print('candidates:', len(CANDS))
