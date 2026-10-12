# Aegis 🛡️

**Infrastructure-as-Code security scanner — 346 rules, 100% recall, ~520× faster than Checkov.**

Aegis scans Terraform, Dockerfiles, Kubernetes manifests and plan JSON,
builds a resource relationship graph, and reports misconfigurations with
file-and-line evidence — including full **attack paths** from the internet
to your data stores.

![Rules](https://img.shields.io/badge/rules-346-blue)
![Go](https://img.shields.io/badge/go-1.25-00ADD8)
![License](https://img.shields.io/badge/license-MIT-green)

## Quick start

```bash
go build -o aegis ./cmd/aegis

./aegis doctor                          # self-check: 346 rules loaded
./aegis scan ./my-infra                 # text report
./aegis scan ./my-infra --format=json --fail-on=high   # CI mode
./aegis scan ./my-infra --attack-paths  # evidence-backed kill chains
./aegis fix ./my-infra                  # safe fixes (dry run by default)
./aegis quality-gate                    # release gates: precision/recall/perf
```

## Features

- **346 detection rules** — 245 AWS, 25 Azure, 24 GCP, 10 Docker, 3 Kubernetes,
  9 supply-chain, 8 Terraform
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

## Aegis vs Checkov (held-out benchmark, 200 projects)

| Metric | Aegis 1.0.0 | Checkov 3.3.26 |
|--------|------------:|---------------:|
| Precision | 0.700 | 0.700 |
| Recall | **1.000** | 1.000 |
| F1 | 0.824 | 0.824 |
| Median scan time | **7.8 ms** | 4,054 ms |

Detection tied; Aegis ~520× faster. Unique to Aegis: attack-path chains,
secret taint tracking, Terraform backend security rules, `aegis doctor`.
See [docs/PHASE5_VALIDATION.md](docs/PHASE5_VALIDATION.md) for methodology
and limitations.

## Docs

- [Release notes](docs/RELEASE_NOTES_v1.0.0.md)
- [Changelog](CHANGELOG.md)
- [Coverage matrix](docs/COVERAGE_MATRIX.md) — per-service rule inventory
- [Attack paths](docs/PHASE3_ATTACK_PATHS.md)
- [Production hardening](docs/PHASE4_PRODUCTION.md)
- [Final verdict](docs/FINAL_VERDICT.md) — honest comparison

## Project layout

```
cmd/aegis/            CLI (scan, fix, serve, quality-gate, doctor)
internal/rules/       rule packs: aws, azure, gcp, k8s, supplychain, terraform
internal/attackpath/  kill-chain builder with uncertainty handling
internal/qualitygate/ release-blocking precision/recall/perf gates
internal/remediation/ safe auto-fix with IAM/networking blocklist
internal/graph/       resource relationship graph
internal/report/      text / JSON / SARIF renderers (secrets redacted)
benchmark/            held-out corpus generator + raw results
docs/                 coverage matrix, validation, release notes
examples/             sample vulnerable projects
```
