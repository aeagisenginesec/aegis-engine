# Aegis 🛡️

**Infrastructure-as-Code security scanner — 1,153 rules, deterministic, ~150× faster than Trivy.**

Aegis scans Terraform, CloudFormation, Kubernetes manifests, Dockerfiles,
docker-compose, Bicep, ARM templates, Pulumi YAML and Terraform plan JSON,
builds a resource relationship graph, and reports misconfigurations with
file-and-line evidence — including full **attack paths** from the internet
to your data stores.

![Rules](https://img.shields.io/badge/rules-1153-blue)
![Go](https://img.shields.io/badge/go-1.25-00ADD8)
![License](https://img.shields.io/badge/license-MIT-green)

## Quick start

```bash
go build -o aegis ./cmd/aegis

./aegis doctor                          # self-check: 1,153 rules loaded
./aegis scan ./my-infra                 # text report
./aegis scan ./my-infra --format=json --fail-on=high   # CI mode
./aegis scan ./my-infra --attack-paths  # evidence-backed kill chains
./aegis fix ./my-infra                  # safe fixes (dry run by default)
./aegis quality-gate                    # release gates: precision/recall/perf
```

## Features

- **1,153 detection rules** — AWS, Azure, GCP, Alibaba, OCI, Kubernetes,
  Docker, Compose, supply-chain, Terraform-generic and custom packs
  (see [coverage matrix](docs/COVERAGE_MATRIX.md))
- **Attack paths** (`--attack-paths`) — chains like
  `INTERNET → SG(0.0.0.0/0) → EC2 → IAM role → RDS`, every hop cited with
  evidence; `[UNCERTAIN]` markers instead of guesses
- **Secret taint tracking** — secrets in user data, tags, outputs and variable
  defaults, values redacted in all output
- **Quality gates** (`quality-gate`) — automated precision/recall/performance
  checks that block releases on failure
- **Safe remediation** (`fix`) — dry-run default, minimal diffs, re-parse
  validation; IAM and security groups never auto-patched without `--force`
- **Suppressions & baselines** — `# aegis:ignore=RULE-ID`, stable baseline files
- **YAML custom rules** — user-defined checks without Go
- **Compliance mappings** — CIS AWS 1.5, NIST 800-53, PCI DSS
- **SARIF / JSON / text** output
- **Deterministic** — identical input produces byte-identical output, every run

## Scope — what Aegis is and isn't

Aegis scans **static infrastructure-as-code for misconfigurations**. It does
**not** scan container images, SBOMs, licenses, or live cloud accounts, and
it is **not** a CVE scanner. All benchmark claims below are measured on
IaC-misconfiguration workloads only.

Pulumi programs written in TypeScript/JavaScript, Python, Go, .NET, or Java
are **detected but not analyzed** (a static scanner cannot evaluate them
without executing code, which Aegis never does). The scanner emits a warning
diagnostic naming the unparsed program files, so "0 findings" is never
misread as "clean". See [docs/PULUMI.md](docs/PULUMI.md).

## Aegis vs the field (R4 blind evaluation, 210 projects, 136-concept ground truth)

| Metric | Aegis 2.0.0 | Checkov | KICS | Trivy |
|--------|------------:|--------:|-----:|------:|
| Precision | **1.000** | — | — | 0.469 |
| Recall | **0.904** | — | — | 0.199 |
| F1 | **0.950** | 0.331 | 0.371 | 0.279 |
| Sweep wall time (210 projects) | **2.2 s** | — | — | 324.9 s |

Checkov/KICS F1 from the same frozen R4 pipeline; only Aegis/Trivy sweep
timing was recorded. See
[docs/audit/14_TRIVY_OUTPERFORM_REPORT.md](docs/audit/14_TRIVY_OUTPERFORM_REPORT.md)
for methodology, and the honest-scope note above for what these numbers do
*not* cover (no CVE, image, SBOM or license scanning).

## Docs

- [Release notes](docs/audit/16_RELEASE_NOTES_v2.0.0.md) (v2.0.0; [v1.0.0](docs/RELEASE_NOTES_v1.0.0.md))
- [Changelog](CHANGELOG.md)
- [Coverage matrix](docs/COVERAGE_MATRIX.md) — per-service rule inventory
- [Attack paths](docs/PHASE3_ATTACK_PATHS.md)
- [Production hardening](docs/PHASE4_PRODUCTION.md)
- [Final verdict](docs/FINAL_VERDICT.md) — honest comparison

## Project layout

```
cmd/aegis/            CLI (scan, fix, serve, quality-gate, doctor)
internal/rules/       rule packs: aws, azure, gcp, alibaba, oci, k8s,
                      docker, compose, supplychain, terraform, custom
internal/adapter/     format adapters: terraform, cloudformation, k8s,
                      dockerfile, compose, bicep, arm, pulumi
internal/attackpath/  kill-chain builder with uncertainty handling
internal/qualitygate/ release-blocking precision/recall/perf gates
internal/remediation/ safe auto-fix with IAM/networking blocklist
internal/graph/       resource relationship graph
internal/report/      text / JSON / SARIF renderers (secrets redacted)
benchmark/            held-out corpus generator + raw results
docs/                 coverage matrix, validation, release notes
examples/             sample vulnerable projects
```
