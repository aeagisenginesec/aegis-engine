# Classifier changelog (round 3)

Pre-results (driven by labeler phrasing + Aegis finding titles, before any competitor scanner ran):
- `eks-public-api` class added (labelers used "EKS ... public" phrasing for both cluster-endpoint and private-only-subnets concepts).
- `iam-wildcard`: negatives for CFN `!Sub` artifacts.
- `db-no-encryption`, `db-no-backup`, `volume-unencrypted`: keyword fixes for labeler phrasing.
- `docker-build-tools`: positives for "debug tools installed in image".
- `curl-pipe-shell`, `docker-secret`: positives for labeler phrasing.
- `nsg-open` negative `sg-` guard removed (was blocking Azure NSG phrasing); positives added.
- `sg-open-*`: negative `nsg` to keep Azure NSG out.
- `s3-no-encryption`: positive `sse` removed (was substring-matching "asset"/"classless" in labeler phrasing).
- `k8s-secret-env` vs `secret-hardcoded`: split by "environment" phrasing.
- `compose-privileged` vs `k8s-privileged`/`k8s-host-*`: context negatives.
- `gcp-gke-public`: GKE-context guard.

Post-Aegis-results, pre-final-scoring (finding-title coverage; title→existing-class mappings only, no new classes, no threshold changes):
- `sg-open-ssh` += "ingress open to the world" (Aegis AEGIS-AWS-004 title).
- `kms-no-rotation` += "without rotation" (Aegis AEGIS-AWS-335 title).
- `iam-trust-broad` += "assumable by anyone" (Aegis AEGIS-AWS-101 title).
- `gcs-public` += "publicly readable via iam" (Trivy title; first attempt "publicly readable" over-matched and was narrowed).
- `secret-hardcoded` += "secret in service environment" (Aegis AEGIS-COMPOSE-006 title).
- `sg-open-ssh` += "ingress to ssh" (Trivy AWS-0107 title).
- `s3-public-acl` += "publicly accessible through acl" (Trivy AWS-0092 title).
- `s3-no-logging` += "bucket logging" (Trivy "S3 Bucket Logging" title).
- `db-public` negative += "acl" (disambiguate Trivy ACL title).
- `sg-open-ssh` += "unrestricted access to ssh" (KICS "Security Group With Unrestricted Access To SSH").

A/B label agreement after all changes: 0 diffs, 0 unclassified, 0 multi-class (149/149 pre-adjudication keys; r3111 re-label key added post).
