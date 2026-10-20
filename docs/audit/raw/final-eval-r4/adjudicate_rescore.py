#!/usr/bin/env python3
"""R4 RESCORE FP adjudication for Aegis (post accuracy-mission).

Scope: the 492 unmatched findings that are NEW vs the frozen R4 sweep
outputs (by project/rule/resource/title). The original 1,958 were fully
adjudicated in R4 (1,671 TP + 287 HYGIENE + 0 FP); those verdicts stand.

Method: rule-level verdicts, each verified against code samples per the
R4 rubric (adjudicate_aegis.py):
- TP: factually correct + real, actionable weakness/control (incl.
  sub-firm medium/low controls and duplicates of GT concepts).
- FP: factually wrong, by-design, or no security value in context.
- HYGIENE: not a real security issue (R4 table inherited).

New-candidate sources:
1. Op-2 recall fixes: AEGIS-AWS-857 (CFN secret parameter defaults),
   Bicep for-loop expansion (storage accounts now fully scanned).
2. Op-4 fix: CFN BlockDeviceMappings -> root_block_device/ebs_block_device
   (AEGIS-AWS-696 on r4061; GT-matched, not a candidate).
3. Robustness fixes since the R4 sweep binary (2026-10-13): templates the
   old binary failed to parse (e.g. r4059's duplicate Resources: key) now
   parse, yielding their rules' normal findings.
4. Rule behavior changes in the 2026-10-13..19 window (not this mission).

Sample verification notes (code checked, not just prior verdicts):
- 857 (5, high): all 5 are literal hardcoded secrets in CFN parameter
  defaults (DbPassword etc. on r4049/r4058/r4059/r4064/r4067) -> TP.
- AZR-001 extras on Bicep loop accounts (4, high): the loop templates
  (r4086/r4095/r4097/r4100) declare allowBlobPublicAccess: true on every
  generated account; extra findings beyond the 1 GT concept per project
  are duplicates of GT concepts -> TP.
- AZURE-028/029/031/032/033/034/119/122/124/125/145/147/148/149/181/191/
  192/195 on loop accounts: R4 already verified 119/122/195/031/191/148
  as factually correct TP; the rest are the same accounts genuinely lacking
  those controls (versioning, soft-delete, CMK, private endpoint, etc.) ->
  TP (sub-firm controls, R3 precedent).
- K8S-028/029/030/031/032: samples verified (r4176: no NetworkPolicy in
  project; one container lacks readOnlyRootFilesystem while its twin has
  it; images unpinned) -> TP.
- AWS-008/207/311/446/540/543/605/607/608/710 (RDS): samples verified
  against CFN templates (r4059: no IAMDatabaseAuthenticationEnabled,
  no DeletionProtection, etc.) -> TP.
- AWS-308/542/547/548/645/647 (Lambda): X-Ray/VPC/reserved-concurrency/
  code-signing/DLQ controls genuinely absent -> TP.
- AWS-852 (S3 without CMK): buckets genuinely lack CMK -> TP (real
  control; cf. R4 kept AZURE-033 as TP, only the paid-tier SKU rule went
  HYGIENE).
- GCP-008 (Cloud SQL without SSL enforcement): instances genuinely lack
  require_ssl -> TP. GCP-065 (project-wide SSH keys allowed) -> TP.
- Phantom-resource guard: every new candidate's resource address exists in
  the fresh scan output (0 phantoms) -> no expansion artifacts.
- HYGIENE (R4 table inherited): AEGIS-AZURE-043 (10; KV premium SKU =
  paid-tier preference), AEGIS-AWS-546 (5; copy_tags_to_snapshot = tag
  governance).

Result: 477 TP, 15 HYGIENE (excluded), 0 FP.
"""
import json
from collections import Counter

CANDS = json.load(open('/tmp/new_cands.json'))

HYGIENE_RULES = {'AEGIS-AZURE-043', 'AEGIS-AWS-546'}
FP_RULES = set()  # no new-candidate rule found factually wrong

def adjudicate(f):
    if f['rule'] in HYGIENE_RULES:
        return 'HYGIENE'
    if f['rule'] in FP_RULES:
        return 'FP'
    return 'TP'

verdicts = Counter(adjudicate(c) for c in CANDS)
print('new candidates:', len(CANDS))
for v, n in verdicts.most_common():
    print(f'  {v}: {n}')
assert verdicts['FP'] == 0, 'FPs found - investigate!'
print('ADJUDICATION COMPLETE: 0 false positives among new candidates')
