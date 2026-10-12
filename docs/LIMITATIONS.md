# Known Limitations

Honest list of what Aegis cannot do (1,185 rules, 2026-10-12).

## Coverage gaps

- **CloudFormation / ARM / Bicep / Pulumi are not supported.** Terraform HCL,
  Dockerfiles, Docker Compose, and Kubernetes manifests only.
- **KICS covers more IaC formats** (17 platforms, 1,810 queries). Aegis focuses
  on depth in Terraform/Docker/K8s rather than breadth across every format.
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

- **Hygiene rules are noisy by design.** Roughly 30% of findings on minimal
  projects are low-severity operational suggestions (lifecycle policies,
  notifications, backup retention). Filter with `--fail-on=medium` or higher
  in CI; low-severity findings are reported separately, not counted in
  precision metrics.
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
| Non-Terraform IaC formats | KICS (CloudFormation, ARM, Pulumi, etc.) |

## Recently fixed (no longer limitations)

- Dynamic `dynamic` block expansion (fixed 2026-10-12)
- `data "aws_iam_policy_document"` resolution (fixed 2026-10-12)
- Module expansion intra-module reference rewriting (fixed 2026-10-11)
- `jsonencode()` IAM policy resolution (fixed 2026-10-11)
- Alibaba Cloud and OCI rule packs (added 2026-10-12)
- Azure/GCP rule depth (expanded to 313/285 rules, 2026-10-12)
- Docker/Compose/K8s rule depth (expanded 2026-10-12)
