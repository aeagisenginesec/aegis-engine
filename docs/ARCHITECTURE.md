# Aegis Architecture

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌────────────┐
│  discovery  │────▶│   adapter    │────▶│      ir       │────▶│   rules    │
│  .tf files  │     │  HCL → AST   │     │  normalized   │     │  587 checks│
└─────────────┘     └──────────────┘     │  resources    │     └────────────┘
                                        └───────────────┘            │
                                               │                    ▼
                                        ┌───────────────┐     ┌────────────┐
                                        │    graph      │◀────│ suppress   │
                                        │  relationships│     │ baselines  │
                                        └───────────────┘     └────────────┘
                                               │                    │
                                               ▼                    ▼
                                        ┌───────────────┐     ┌────────────┐
                                        │  attackpath   │────▶│   report   │
                                        │  kill chains  │     │ text/json/ │
                                        └───────────────┘     │ sarif      │
                                                              └────────────┘
```

## Pipeline stages

### 1. discovery (`internal/discovery`)
Walks the target directory recursively, collecting `.tf` (and Dockerfile)
files. Enforces caps: 10MB/file, 256MB total, 20,000 files — prevents OOM
on pathological inputs. Output: list of files with sizes.

### 2. adapter (`internal/adapter`)
Parses HCL into an AST, then normalizes into `ir.Resource` values. Key
responsibilities:
- **Pre-validation** (`hardening.go`): null bytes, UTF-16, unbalanced
  braces, nesting depth — explicit errors, never silent clean.
- **Unknown tracking**: variables, data sources, `count`/`for_each` produce
  `Known=false` values with `Ref` pointers. Rules must handle unknowns.
- **Inline suppressions**: `# aegis:skip=RULE-ID` comments attach to
  resources.

### 3. ir (`internal/ir`)
The intermediate representation. `Resource` has a stable `Address()`
(`aws_s3_bucket.data`), typed `Attributes` (each with `Known` bool),
`Blocks` (nested blocks like `ingress`), and `Span` (file:line).
`Finding` carries rule ID, severity, evidence, attack path, compliance
refs, remediation, and references. Everything downstream reads IR —
never raw HCL.

### 4. rules (`internal/rules`)
587 rules across packs: `aws`, `azure`, `gcp`, `docker`, `k8s`,
`supplychain`, `terraform`. Two interfaces:
- `Rule.Check(resource)`: single-resource checks (most rules).
- `CrossResourceRule.CheckAll(resources)`: needs the full set (attack
  paths, companion correlation, IAM chains).

The engine (`engine.go`) parallelizes across `runtime.NumCPU` workers with
strict isolation: each rule writes only its own findings slice; the shared
resource list is read-only; output is deterministically re-sorted.

After rules run: `EnrichCompliance` (CIS/NIST/PCI mappings),
`EnrichRemediation` (fix code + doc links), `ApplyInlineSuppressions`,
`ApplyBaseline`.

### 5. graph (`internal/graph`)
Builds resource relationships from references (`Ref` fields): security
group → instance, IAM role → policy → workload, ALB → target → EC2.
Used by attack-path rules and companion correlation.

### 6. attackpath (`internal/attackpath`)
Assembles evidence-backed kill chains: entry point (public SG/ALB) →
workload (EC2/Lambda) → data (RDS/S3). Each hop cites resource +
attribute + file:line. Unresolvable hops are marked `UNCERTAIN`, never
invented.

### 7. report (`internal/report`)
Renders `ir.ScanResult` as text, JSON, or SARIF 2.1.0. Redacts
secret-looking evidence values (`password`, `secret`, `token`, `key`)
before emitting.

## Supporting packages

| Package | Purpose |
|---------|---------|
| `qualitygate` | Release gates: precision/recall, rule coverage, perf p95, parser safety |
| `remediation` | `aegis fix`: minimal diffs, dry-run default, IAM/networking blocklist |
| `perf` | Benchmarks + CI performance gates |
| `regression` | Golden-file + labeled-corpus regression tests |
| `semantics` | Shared helpers: severity ranking, string extraction |
| `advisories` | Threat-advisory feed for supply-chain rules |
| `version` | Build-time version stamping |

## Key design decisions

- **IR-first**: rules never parse HCL directly — testable, deterministic.
- **Fail closed**: absent attributes with insecure provider defaults are
  flagged, not passed.
- **Unknowns are explicit**: `Known=false` propagates; rules return nil
  rather than guess.
- **Deterministic output**: same input → byte-identical findings (verified
  by hash across 10 runs).
- **Additive safety**: suppressions and baselines apply *after* rules run;
  rule logic stays pure.
