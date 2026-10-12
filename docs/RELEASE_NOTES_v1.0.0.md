# Aegis v1.0.0 — Release Notes

## What is Aegis?

Aegis is a fast, evidence-driven Infrastructure-as-Code security scanner.
It reads Terraform (plus Dockerfiles, Kubernetes manifests and plan JSON),
builds a resource relationship graph, and reports misconfigurations with
file-and-line evidence — including full attack paths from the internet to
your data stores. It is written in Go, needs no database, and scans a
typical project in milliseconds.

## Key numbers

- **346 detection rules**: 245 AWS, 25 Azure, 24 GCP, 10 Docker, 3 Kubernetes,
  9 supply-chain, 8 Terraform
- **100% recall** on a 200-project held-out benchmark (caught every planted
  vulnerability)
- **~520× faster than Checkov** (7.8ms vs 4,054ms median on the same corpus)
- **22 packages, 1000+ tests**, race-detector clean

## Quick start

```bash
# Build
go build -o aegis ./cmd/aegis

# Check it's healthy
./aegis doctor

# Scan a Terraform project
./aegis scan ./my-infra --format=text

# JSON output (for CI)
./aegis scan ./my-infra --format=json --fail-on=high

# Show evidence-backed attack paths
./aegis scan ./my-infra --attack-paths

# Propose safe fixes (dry run by default)
./aegis fix ./my-infra

# Run the release gates
./aegis quality-gate
```

## What's new in 1.0.0

- **Attack-path analysis** (`--attack-paths`): instead of isolated findings,
  Aegis chains them — `INTERNET → SG(0.0.0.0/0) → EC2 → IAM role → RDS` —
  with every hop citing the exact resource and line. Unknown values get an
  explicit `[UNCERTAIN]` marker rather than a guessed hop.
- **Quality gates** (`quality-gate`): precision, recall, rule coverage,
  performance and parser-safety checks that block releases on failure.
- **Production hardening**: fuzz-tested parser, zero data races, golden-file
  regression suite, remediation blocklist for IAM/networking.
- **Top-20 coverage gaps closed**: IAM key rotation, NotAction bypass,
  Transit Gateway, KMS deletion windows, Security Hub, Detective and more.

## Honest limitations

- **Precision is ~70–83%, below our 95% target.** The gap is hygiene noise
  (lifecycle, logging, monitoring suggestions) on otherwise-clean projects —
  not missed vulnerabilities. Recall is 100%.
- **Benchmarks are synthetic.** The held-out corpus is generated, not
  real-world repositories. Speed ratios are robust; absolute times are
  single-machine measurements.
- **Terraform-first.** Dockerfile, Kubernetes and plan-JSON support exist but
  the rule depth is greatest for Terraform AWS.
- **No auto-remediation of IAM or security groups** without `--force` — by
  design, these need human review.

## Further reading

- [Coverage matrix](COVERAGE_MATRIX.md) — what each AWS service covers
- [Phase 5 validation](PHASE5_VALIDATION.md) — rigorous benchmark methodology
- [Final verdict](FINAL_VERDICT.md) — honest per-metric comparison vs Checkov
- [Production hardening](PHASE4_PRODUCTION.md) — what was hardened and why
- [Changelog](../CHANGELOG.md) — full change history
