#!/usr/bin/env python3
"""R4 adjudication + final labeling QA. Run after label_r4.py."""
import json, importlib.util
from collections import defaultdict, Counter

BASE = '.'
B = json.load(open('labels/labels-B.json'))
A = json.load(open('labels/labels-A.json'))
gt = [{'project': d['project'], 'format': d['format'], 'resource': d['resource'],
       'condition': d['condition'], 'severity': d['severity']} for d in B]
gt.sort(key=lambda x: (x['project'], x['condition']))
json.dump(gt, open('ground-truth.json', 'w'), indent=1)
log = json.load(open('labels/adjudication-log.json'))
log.update({
    'n_firm_A': len(A), 'n_firm_B': len(B),
    'pre_adjudication_key_agreement': '114/159 (71.7%) Jaccard at (project, class, resource); class-level agreement 133/137 (97.1%) - remaining key disagreements are resource attribution, not class.',
    'n_firm_concepts': len(gt),
    'adjudication_decisions': log['adjudication_decisions'] + [
        'Round 2 of labeling QA: CFN ingress-span bug (span ran past SecurityGroupEgress into Parameters, mislabeling sg-open-world on cfn_sg_intrinsic) fixed; TF resource-declaration quote bug fixed for gke/no-waf/no-flowlog/no-audit/gcp-cmek rules; eks-public-api CFN + s3-public-acl Pulumi patterns added (prior patch was a silent no-op); volume-unencrypted gate extended to inline BlockDeviceMappings (CFN EBS); r4061 imdsv1 accepted (EC2 with inline unencrypted EBS, no metadata options - generator did not intend it, code fact wins); r4124 git-exposed NOT labeled (dk_gitexposed block contains no .git evidence - generator block defect, disclosed).'],
})
json.dump(log, open('labels/adjudication-log.json', 'w'), indent=1)
print('GT:', len(gt))

spec = importlib.util.spec_from_file_location('sc', 'score.py')
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)
bad = [(d['project'], d['class']) for d in B
       if d['class'] not in sc.classify(d['condition'] + ' ' + d.get('resource', ''))]
print('unclassifiable GT:', bad)
man = {m['id']: m for m in json.load(open('corpus/MANIFEST.json'))}
print('SECURE-PROFILE FIRM:', [d['project'] for d in B if man[d['project']]['profile'] == 'secure'])
plan = json.load(open('sealed/injection-plan.json'))
gt_by_proj = defaultdict(set)
for d in B:
    gt_by_proj[d['project']].add(d['class'])
inj_not_gt = Counter()
gt_not_inj = Counter()
for pid, v in plan.items():
    inj = set(v['injected_concepts_corrected'])
    g = gt_by_proj.get(pid, set())
    for c in inj - g:
        inj_not_gt[c] += 1
    for c in g - inj:
        gt_not_inj[c] += 1
print('injected-not-GT:', dict(inj_not_gt))
print('GT-not-injected:', dict(gt_not_inj))
print('per-class:', dict(sorted(Counter(d['class'] for d in B).items())))
print('projects w/ firm:', len(gt_by_proj))
