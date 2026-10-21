# Known Limitations

Honest list of what Aegis cannot do (1,140 active rules, 67 deprecated,
2026-10-20).

## Coverage gaps

- **Blind-corpus recall is the frontier.** On the sealed R5 blind corpus
  (210 projects, 128 concepts) recall is 0.555. The missed classes are
  coverage gaps, not misreads: hardcoded secrets in template parameter
  defaults, Pulumi config, `.env` files and K8s env literals
  (31 of 57 misses); admin ports public by SG *rule composition*;
  ECR public repository policies; Compose published database ports;
  API Gateway without authorizers; public EBS snapshots; K8s
  CAP_SYS_ADMIN; MSK/Kafka plaintext listeners. See
  `docs/audit/26_AEGIS_FINAL_STATE.md` for the full FN profile.
- **One known factual false-positive family: AEGIS-AWS-001.** The rule
  demands explicit SSE configuration on S3 buckets, but S3 has applied
  SSE-S3 by default since January 2023, so a bucket with no explicit
  configuration is encrypted at rest and the claim "without server-side
  encryption" is wrong for it (6 verified instances on the R5 corpus).
- **Same-named instances in one file share one resource identity.** Two
  Deployments with the same name in a single multi-document YAML file
  (a vulnerable and a hardened twin) both surface as
  `k8s_Deployment.<name>`; a finding names the resource, and the span
  is the only way to tell which instance it belongs to.
- **KICS covers more IaC formats** (17 platforms, 1,810 queries). Aegis
  covers Terraform, CloudFormation, ARM, Bicep, Pulumi, Dockerfiles,
  Docker Compose, and Kubernetes manifests in depth.
- **Container image scanning is out of scope.** Use Trivy or Grype for image
  layers; Aegis covers Dockerfile and Compose misconfigurations only.

## Analysis limitations

- **Unresolved values are conservative — by design.** Variables without defaults,
  data sources (other than `aws_iam_policy_document`), and module outputs are
  marked unknown with explicit `UNCERTAIN` markers. Rules that need a concrete
  value stay silent rather than guess. This avoids false positives but means
  some misconfigurations are missed when values come from outside the scanned
  code. Unresolvable `dynamic` block `for_each` expressions produce warning
  diagnostics rather than silent skips.
- **Attack paths are illustrative**, not proofs of exploitability. A kill chain
  shows configuration relationships (public exposure → permissive IAM →
  unencrypted data), not a tested exploit.
- **Findings are heuristics.** Severity is a judgment call informed by CIS/NIST
  mappings, not a CVSS score. Triage before treating as ground truth.

## Operational limitations

- **Hygiene rules are noisy by design.** On the R5 blind corpus, hygiene-class
  rules were ~34% of raw findings — low-severity operational suggestions
  (lifecycle policies, notifications, backup retention). Filter with
  `--fail-on=medium` or higher in CI; low-severity findings are reported
  separately, not counted in precision metrics.
- **Large repos scale linearly** (~40KB RAM per resource). A 100k-resource repo
  needs ~4GB. The 10MB per-file cap bounds file size, not resource count.
- **No incremental/diff scanning.** Every run is a full scan. (Median 55–70ms
  per project keeps this cheap in practice.)
- **`--timeout` bounds CLI wait time** but does not cancel a mid-scan
  goroutine; the in-progress scan runs to completion.
- **Linux AMD64 builds only.** No Windows/macOS binaries published.
- **Releases are unsigned.** No GPG/cosign signing in the current build
  environment; checksums (SHA-256) are published per release.

## What to use alongside Aegis

| Need | Tool |
|------|------|
| Runtime CSPM | AWS Security Hub, GuardDuty, Prisma Cloud |
| Container image scanning | Trivy, Grype |
| Secrets in git history | gitleaks, trufflehog |
| Application SAST | Semgrep, Snyk Code |
| K8s runtime policy | OPA Gatekeeper, Kyverno |
| IaC formats beyond the eight above | KICS |

## Recently fixed (no longer limitations)

- CloudFormation / ARM / Bicep / Pulumi adapters (added after 2026-10-12;
  earlier revisions of this document listed these formats as unsupported)
- Security-group database-port exposure rule, AEGIS-AWS-858; AKS RBAC via
  the real ARM/Bicep `enableRBAC` spelling; Compose host-network split
  (AEGIS-COMPOSE-009) and `ipc` extraction (Sprint 1, 2026-10-20)
- 15 duplicate rules deprecated (registry 1,155 → 1,140); Docker
  image-metadata rules judge only the final build stage (Sprint 2,
  2026-10-20)
- ARM/Bicep storage child services (`blobServices`/`queueServices`) were
  folded onto a phantom storage account and never reached the real one;
  VNet `enableDdosProtection`/`ddosProtectionPlan` collided on one IR
  attribute and resolved nondeterministically, intermittently firing
  AEGIS-AZURE-057 on compliant VNets (Sprint 3 / closeout, 2026-10-20)
- Dynamic `dynamic` block expansion (fixed 2026-10-12)
- `data "aws_iam_policy_document"` resolution (fixed 2026-10-12)
- Module expansion intra-module reference rewriting (fixed 2026-10-11)
- `jsonencode()` IAM policy resolution (fixed 2026-10-11)
- Alibaba Cloud and OCI rule packs (added 2026-10-12)
- Azure/GCP rule depth (expanded to 313/285 rules, 2026-10-12)
- Docker/Compose/K8s rule depth (expanded 2026-10-12)
