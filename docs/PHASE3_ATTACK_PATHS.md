# Phase 3: Attack-Path Analysis — Aegis's Differentiator

## What was built

A new `internal/attackpath/` package that transforms flat findings into
**evidence-backed kill chains**. Instead of reporting isolated issues,
Aegis now shows the complete path an attacker would take:

```
INTERNET
  │
  ▼
[NETWORK]  aws_security_group.web — allows ingress from 0.0.0.0/0
  │ evidence: ingress.cidr_blocks = "0.0.0.0/0" @ main.tf:7
  ▼
[WORKLOAD] aws_instance.web — EC2, potential stepping stone
  ▼
[IAM]      aws_iam_role.app — assumed by workload
  ▼
[IAM]      aws_iam_policy.admin — grants: *
  ▼
[DATA]     aws_db_instance.prod — sensitive data objective
```

## New rules

| ID | Title | Severity |
|----|-------|----------|
| AEGIS-AWS-629 | Full kill chain: internet to data store | Critical (with IAM) / High |
| AEGIS-AWS-630 | IAM privilege chain: workload inherits sensitive actions | High |

Total rules: **326** (was 324).

## Key design decisions

### 1. Evidence-backed hops (never invented)

Every hop cites:
- The Terraform resource (`aws_security_group.web`)
- The attribute (`ingress.cidr_blocks`)
- The file and line (`main.tf:7`)
- The actual value found

### 2. Explicit uncertainty (never silent)

When variables, data sources, or unknown values prevent a definitive
conclusion, the hop is marked:

```
[UNCERTAIN: value comes from a variable — actual value unknown at scan time]
```

The chain still reports — the uncertainty IS the finding.

### 3. Confidence scoring

- **High**: all hops use concrete literal values
- **Medium**: some hops rely on resolvable references
- **Low**: any hop involves variables, conditionals, or data sources

Chain confidence = minimum hop confidence.

### 4. IAM privilege tracing

Traces `aws_iam_role` → `aws_iam_policy` → `aws_instance`/`aws_lambda_function`:
- Via `aws_iam_role_policy_attachment`
- Via `aws_iam_instance_profile` → role
- Detects wildcard (`*`) and sensitive actions (`iam:*`, `s3:*`, `sts:AssumeRole`, `iam:PassRole`)

## CLI

```bash
# Show only attack chains as ASCII diagrams
aegis scan ./infra --attack-paths

# JSON output with full chain evidence
aegis scan ./infra --attack-paths --format=json
```

## Files

- `internal/attackpath/chain.go` — Chain, Hop, Confidence types
- `internal/attackpath/builder.go` — entry/workload/data/IAM detection
- `internal/attackpath/killchain.go` — chain assembly, SG resolution
- `internal/attackpath/uncertainty.go` — UNCERTAIN classification
- `internal/attackpath/render.go` — ASCII diagram rendering
- `internal/rules/aws/attack_paths_killchain.go` — rules 629, 630
- `internal/report/report.go` — WriteAttackPathsText/JSON
- `cmd/aegis/main.go` — `--attack-paths` flag
- `internal/graph/graph.go` — added `HasEdge()` helper

## Tests

- `internal/attackpath/attackpath_test.go` — 7 tests: complete chain,
  uncertain chain, broken chain, uncertainty classification, ASCII render,
  IAM chain
- `internal/rules/aws/attack_paths_killchain_test.go` — 4 tests: 629
  fires, 629 clean, 630 fires, 630 clean

All 21 packages pass. `go vet` clean. `gofmt` clean.
