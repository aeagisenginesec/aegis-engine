# Aegis Threat Model

## What Aegis protects against

Aegis is a static IaC scanner. It detects **misconfigurations in Terraform
code before deployment**:

- Unencrypted data stores (S3, RDS, EBS, EFS)
- Public network exposure (open security groups, public S3/RDS)
- Overly permissive IAM (wildcard actions, privilege-escalation primitives)
- Hardcoded secrets in configuration
- Missing audit logging (CloudTrail, S3 access logs)
- Weak transport security (HTTP listeners, old TLS)

It models **attack paths**: chains from internet entry points through
workloads to data stores, with per-hop evidence.

## What Aegis does NOT protect against

- **Runtime attacks.** Aegis never sees a running system. It cannot detect
  active exploitation, malware, or compromised credentials in use.
- **Application-layer vulnerabilities.** SQL injection, XSS, auth bypass in
  your code are out of scope — use SAST/DAST for those.
- **Supply-chain compromise of providers.** Aegis trusts the Terraform
  provider schemas it parses against.
- **Secrets already deployed.** Aegis flags hardcoded secrets so you can
  rotate them; it does not rotate them for you.
- **Cloud control-plane misconfigurations** made via console/CLI (not in
  Terraform). Aegis only sees what's in code.
- **Zero-days in AWS/GCP/Azure services.** Aegis checks *your*
  configuration, not the provider's.

## Trust boundaries

| Boundary | Trust assumption |
|----------|------------------|
| Input `.tf` files | Treated as **untrusted**: malformed input must produce errors, never silent clean (enforced by quality gate) |
| Rule registry | Trusted: rules ship with the binary; custom YAML rules are user-supplied and run with the same privileges as built-ins |
| Scan output | Findings are **advisory**: severities are heuristics, not guarantees |
| Remediation | `aegis fix` is dry-run by default; `--apply` writes files the user owns |

## Attacker model

The assumed attacker has network access to the internet and exploits
**configuration weaknesses** (public S3 buckets, open security groups,
leaked credentials). Aegis does not model insider threats, social
engineering, or physical access.

## Findings are not proofs

A finding means "this configuration matches a known-insecure pattern." It
does not mean the resource is exploitable *right now* — compensating
controls outside Terraform (SCPs, network firewalls, WAF rules) may mitigate
it. Triage accordingly.
