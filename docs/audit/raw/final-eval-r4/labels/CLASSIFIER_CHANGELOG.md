# R4 classifier changelog (score.py CLASS_RULES)

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

## Deliberately NOT done: semantic title mappings

Unlike round 3 (which added 10 finding-title mappings after seeing Aegis
results), R4 adds NO semantic title->class mappings after seeing results.
Near-misses found in auto-scoring (e.g. Aegis "Load balancer target group
uses plain HTTP" vs GT `alb-public`; Aegis "Security group ingress open to
the world" vs GT `sg-open-db`; Aegis "CosmosDB account without IP range
filter" vs GT `db-public`; Aegis "AKS cluster without Azure AD RBAC
integration" vs GT `aks-no-rbac`) are reported as matcher limitations /
near-misses in the final report, NOT rescored. Post-hoc semantic mappings
would be tuning risk on a release-critical eval.
