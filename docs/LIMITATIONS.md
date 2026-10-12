# Known Limitations

Honest list of what Aegis cannot do (v1.0.0, 587 rules).

## Coverage gaps

- **Azure/GCP are thinner than AWS.** 267 AWS rules vs ~95 Azure / ~100
  GCP. Alibaba Cloud, OCI, and other providers are not covered.
- **Kubernetes/Docker rules are minimal** (3 K8s, 10 Docker). Not a
  replacement for kube-bench, Trivy, or Checkov's K8s checks.
- **CloudFormation/ARM/Bicep/Pulumi are not supported.** Terraform HCL
  only (plus Dockerfile scanning).

## Analysis limitations

- **Unresolved values are conservative.** Variables without defaults, data
  sources, and module outputs are marked unknown — rules that need a
  concrete value stay silent rather than guess. This avoids false
  positives but means some misconfigurations are missed when values come
  from outside the scanned code.
- **`jsonencode()` IAM policies are not resolved to strings.** IAM rules
  may miss policies built with `jsonencode()`.
- **No cross-file variable resolution across module boundaries** for some
  companion rules (known defect: module expansion renames resources
  without rewriting intra-module refs).
- **Attack paths are illustrative**, not proofs of exploitability. A chain
  shows configuration relationships, not a tested exploit.

## Operational limitations

- **Findings are heuristics.** Severity is a judgment call, not a CVSS
  score. Triage before treating as ground truth.
- **Hygiene rules are noisy by design.** ~30% of findings on minimal
  projects are low-severity operational suggestions (lifecycle policies,
  notifications). Filter with `--fail-on=medium` or higher in CI.
- **Large repos scale linearly** (~40KB RAM per resource). A 100k-resource
  repo needs ~4GB. The 256MB discovery input cap bounds file size, not
  resource count.
- **`--timeout` does not cancel mid-scan.** It bounds CLI wait time but
  the in-progress scan goroutine runs to completion.
- **No incremental/diff scanning.** Every run is a full scan.

## What to use alongside Aegis

| Need | Tool |
|------|------|
| Runtime CSPM | AWS Security Hub, GuardDuty, Prisma Cloud |
| Container image scanning | Trivy, Grype |
| Secrets in git history | gitleaks, trufflehog |
| Application SAST | Semgrep, Snyk Code |
| K8s runtime policy | OPA Gatekeeper, Kyverno |
