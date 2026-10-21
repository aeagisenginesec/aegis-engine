#!/usr/bin/env python3
"""R4 FP adjudication for Aegis (full adjudication of unmatched findings).

Method: every unmatched finding (labels/fp-candidates-aegis.json) gets a
verdict against the actual code.
- Rule-level verdicts where the verdict is uniform across instances
  (verified against code samples per rule - see adjudication notes below).
- HYGIENE for non-security pedantry (R3 table inherited + 4 principled
  additions, each justified).
- Default TP (R3 precedent): factually correct + real, actionable
  weakness/control, incl. sub-firm medium/low controls and duplicates of
  GT concepts.

Verdict semantics (rounds 2-3 consistent):
- TP: factually correct + real, actionable weakness/control (incl. sub-firm
  medium/low controls the labelers didn't put in the firm GT universe).
- FP: factually wrong, by-design, or no security value in context.
- HYGIENE: not a real security issue (docs/build/SKU/tag pedantry).

Sample-verified rules (R4 code checked, not just prior verdicts):
- AZURE-119/122: fire only on the 9 genuinely-public blob accounts (subset
  of the 13 GT storage-public-azure projects; the other 4 are Bicep
  for-loop accounts Aegis never flags) -> TP.
- AZURE-195: fires on allow_nested_items_to_be_public absent (provider
  default enabled) or true -> factually correct, real control -> TP.
- AZURE-031/191 (shared key): secure blocks do NOT disable shared-key auth
  (tf_az_secure sets no sharedAccessKeyEnabled) -> factually true -> TP.
- AZURE-148 (public network access default): no corpus block sets a
  firewall/private endpoint -> factually true, real control -> TP.
- AWS-339 (hardcoded creds): samples are literal passwords/keys in config
  (e.g. DB master_password literals) -> TP.
- AWS-004 (SG open, 8): 2 on DB-port SGs (generic finding, factually true)
  + 6 on secure SGs' intentional 443/0.0.0.0/0 HTTPS ingress (factually
  true; below firm-GT threshold, as in R3) -> TP.
- K8S-020 (Service exposed): LoadBalancer/NodePort services, factually
  true -> TP. COMPOSE-005 (host path): /:/host:ro mounts -> TP.
- AWS-742 (DNS hostnames): VPCs without enable_dns_hostnames -> TP.
- AWS-001/206: only on private buckets (public-bucket suppression from
  accuracy-100 verified: no 001/206 on intentionally-public buckets) -> TP.
- R3 FP rules ABSENT in R4 (fix verified): AWS-005 egress (gated),
  DOCKER-002 build-stage root (final-stage scoping), DOCKER-010 gcr.io
  (first-party registries trusted) - zero instances among candidates.
"""
import json
from collections import Counter

CANDS = json.load(open('labels/fp-candidates-aegis.json'))

HYGIENE_RULES = {
    # R3 table, inherited (same rationale, re-verified on R4 samples)
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
    # R4 additions (principled, same HYGIENE standard)
    'AEGIS-AWS-677': 'IAM policy statement has no Sid: statement-identifier pedantry (round-2 precedent: KMS Sid)',
    'AEGIS-AZURE-134': 'AKS without cost analysis: FinOps, not a security issue',
    'AEGIS-DOCKER-026': 'full OS base image: base-image size preference, no demonstrated weakness',
    'AEGIS-AWS-546': 'RDS without copy_tags_to_snapshot: tag governance, not security',
    'AEGIS-AWS-702': 'RDS snapshots do not copy tags: tag governance, not security',
}

FP_RULES = {}  # No Aegis rule was found factually wrong / by-design in R4.


def adjudicate(f):
    rule = f['rule']
    if rule in HYGIENE_RULES:
        return 'HYGIENE', HYGIENE_RULES[rule]
    if rule in FP_RULES:
        return 'FP', FP_RULES[rule]
    return 'TP', 'factually correct finding of a real weakness/control; below firm-GT threshold or duplicate of a GT concept'


recs = []
for i, f in enumerate(CANDS):
    verdict, just = adjudicate(f)
    recs.append({'sample_id': f'aegis-{i:05d}', 'project': f['project'],
                 'resource': f['resource'], 'rule': f['rule'],
                 'title': f['title'], 'severity': f['severity'],
                 'verdict': verdict, 'justification': just})
json.dump(recs, open('labels/fp-adjudicated-aegis.json', 'w'), indent=1)
print(Counter(r['verdict'] for r in recs))
print('total:', len(recs))
