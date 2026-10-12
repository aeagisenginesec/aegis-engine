# CI Integration

Run Aegis in CI to block merges with new security findings. Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Clean (or findings below `--fail-on` threshold) |
| 1 | Findings at or above `--fail-on` threshold |
| 2 | Usage error or scan failure (bad flag, unreadable directory) |

`--fail-on` accepts `critical`, `high`, `medium`, `low`. Default (no flag):
any finding exits 1.

## GitHub Actions

```yaml
# .github/workflows/aegis.yml
name: aegis-scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"
      - name: Build aegis
        run: go build -o aegis ./cmd/aegis
      - name: Scan
        run: ./aegis scan . --format=sarif --fail-on=high > aegis.sarif
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: aegis.sarif
```

Findings appear in the repository's **Security** tab. A full example lives in
`examples/github-actions/aegis.yml`.

## GitLab CI

```yaml
# .gitlab-ci.yml
aegis-scan:
  image: golang:1.25
  script:
    - go build -o aegis ./cmd/aegis
    - ./aegis scan . --format=json --fail-on=high > aegis.json
  artifacts:
    reports:
      sast: aegis.json   # GitLab SAST report (SARIF also accepted)
  allow_failure: false
```

## Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: aegis-scan
        name: aegis IaC scan
        entry: aegis scan
        args: [--fail-on=high, .]
        language: system
        files: '\.tf$'
        pass_filenames: false
```

## Jenkins

```groovy
// Jenkinsfile
pipeline {
  agent any
  stages {
    stage('Aegis scan') {
      steps {
        sh 'go build -o aegis ./cmd/aegis'
        sh './aegis scan . --format=sarif --fail-on=high > aegis.sarif'
      }
    }
  }
  post {
    always {
      recordIssues(
        enabledForFailure: true,
        tools: [sarif(pattern: 'aegis.sarif')]
      )
    }
  }
}
```

## Baselines in CI

Suppress known-accepted findings so CI only flags new issues:

```bash
# One-time: capture the current state
aegis scan ./infra --baseline-out=baseline.json

# Commit baseline.json, then in CI:
aegis scan ./infra --baseline=baseline.json --fail-on=high
```

See [BASELINES.md](BASELINES.md) for the metadata format (reasons, owners,
expiry dates).

## Excluding paths

Skip generated, vendored, or out-of-scope paths with KICS-style globs:

```bash
aegis scan ./infra --exclude="vendor/**,*.tfvars" --fail-on=high
```

`*` matches within a path segment, `**` crosses segments, `?` matches one
character; patterns without a leading slash match at any depth. Excluded
files are reported as `skipped` with an explicit reason in scan
completeness (visible in `--format=json`).

## Project config (severity overrides)

Commit an `aegis.yaml` to tune severities per project without forking rules:

```yaml
severity_overrides:
  AEGIS-AWS-001: low      # noisy in this repo
  AEGIS-AWS-004: critical # matters to us
exclude_rules:
  - AEGIS-AWS-558
```

```bash
aegis scan ./infra --config=aegis.yaml --fail-on=high
```

Overrides apply at report time (rule ID, evidence, and remediation stay
intact); invalid severities and unmatched overrides produce warnings, never
hard failures. See [PULUMI.md](PULUMI.md) for the full format.

## Compliance gates

Filter to a benchmark and get a per-control pass/fail summary:

```bash
aegis scan ./infra --compliance=CIS-AWS-1.5
# compliance CIS-AWS-1.5: 42/50 controls passing — FAILING: 1.8, 2.1.1, 3.2
```

Supported frameworks: `CIS-AWS-1.5`, `NIST-800-53`, `PCI-DSS-4.0`. The
summary is also in JSON output as `compliance_summary` for dashboards.

## Mixed-format repositories

`aegis scan` auto-detects every supported format in one run — Terraform,
CloudFormation, ARM, Bicep, Pulumi YAML, Dockerfiles, Kubernetes manifests —
and reports the per-file format in scan completeness. No per-format
invocations needed.

## Monorepos

`aegis scan <dir>` scans recursively — multiple Terraform roots under one
directory are handled as a single scan. Findings carry full file paths, so
per-team ownership can be derived from the path. For separate policy
thresholds per root, run one `aegis scan` per root directory.
