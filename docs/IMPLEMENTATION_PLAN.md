# Aegis Engine — Implementation Plan

Standing plan per the build directive's "required response before implementation".
Updated as milestones land. Go-only. Single binary first.

## 0. Repository findings (2026-10-10)

- **No existing Go codebase.** Greenfield module `aegis`, Go 1.25.4
  (`~/workspace/.go/go/bin/go`). Nothing to preserve, no baseline to regress.
- **Test corpus already exists** (high value, free):
  - `~/workspace/terraform/vuln-three-tier/` — deliberately vulnerable lab.
    Positive corpus: the scanner MUST fire here.
  - `~/workspace/terraform/three-tier/` — production-style reference build.
    Negative corpus: the scanner should stay mostly quiet here.
- **Sibling system**: `~/workspace/aegis-ingestion/` (n8n + Postgres threat-intel
  pipeline) is the *intelligence side*. This repo is the *analysis side*.
  They meet at Milestone 5 (supply-chain intelligence feeds into the engine;
  engine findings can flow back as intelligence events).
- **Only third-party dependency so far**: `github.com/hashicorp/hcl/v2`
  (public API only — never Terraform internals). License review required
  before release (MPL-2.0).

## Milestone 1 — Foundation: a working Go scanner (DONE 2026-10-10)

**Capability**: `aegis scan <dir>` → findings with evidence, exit codes for CI.

| Package | Responsibility | Status |
|---|---|---|
| `internal/ir` | Canonical IR: Span, Value (explicit unknown), Resource, Finding, Evidence, Rule/Adapter interfaces | Done |
| `internal/discovery` | Safe walk: no symlinks, skip .git/.terraform, 10 MiB/file, 256 MiB/scan caps | Done |
| `internal/adapter/terraform` | HCL → IR via hcl/v2, source spans, unknowns explicit | Done (11 tests) |
| `internal/rules` (+`aws`) | Deterministic engine + 12 AWS rules (S3, SG, IAM, RDS, EBS, CloudTrail) | Done (64 tests) |
| `internal/report` | JSON envelope (versioned), SARIF 2.1.0, text; secret redaction | Done |
| `cmd/aegis` | CLI on stdlib `flag`; exit 0 clean / 1 findings / 2 error | Done |

**Design decisions**: unknown values ⇒ no finding (never fail open/closed);
deterministic output (rules sorted, resources sorted); findings carry evidence
(attribute + span + actual vs expected); parse failures become diagnostics,
never silent skips.

**Security/compat risks**: HCL semantic gaps (variables, modules unresolved —
Milestone 2); hcl/v2 is MPL-2.0 (license review before release); no execution
of scanned content (static parse only).

**Acceptance**: `go test ./...` green; `go vet` clean; vuln lab fires findings;
prod project stays quiet; malformed/oversized input → diagnostics, never panic.

## Milestone 2 — Semantics: a Terraform-aware engine (DONE 2026-10-10)

**Capability**: resolve variables, locals, module calls (local paths), resource
references, `terraform plan -json` input; provider schema awareness for AWS.

**Changes**: new `internal/semantics` package (resolver producing resolved IR
with an explicit unknown-set); adapter emits references instead of dropping
them; rules gain access to resolved values; plan JSON becomes a second input
adapter. Unknowns stay explicit — resolution is bounded, never best-effort
guessing.

**Acceptance**: the two-corpus differential (vuln lab vs prod) improves —
fewer false negatives on parameterized configs, no new false positives;
`terraform plan` output for the prod project parses.

## Milestone 3 — Intelligence: graph-based analysis (DONE 2026-10-10)

**Capability**: IAM trust graph, network reachability, cross-resource findings,
evidence-backed attack paths (e.g. public S3 → via bucket policy → data
exfiltration), root-cause correlation.

**Changes**: new `internal/graph` (typed adjacency, in-memory); rules can query
reachability ("is this resource publicly reachable?"); findings link to paths,
not just single resources. Invalid paths are rejected and reported.

**Acceptance**: known attack paths in the vuln lab are found with path
evidence; crafted invalid paths are rejected; uncertainty is labeled.

## Milestone 4 — Remediation: validated fixes and CI/CD (DONE 2026-10-10)

**Capability**: source-aware patch proposals (unified diff), re-scan validation,
regression checks, SARIF + PR comments, policy gates, human approval —
never auto-applies.

**Changes**: new `internal/remediation` (patch generation in an isolated
temp copy, re-scan, diff of findings before/after); CI examples
(GitHub Actions); `aegis scan --fail-on high`.

**Acceptance**: supported fixes (e.g. add S3 encryption block) pass
re-scan with the finding gone and no new findings; patches never touch the
original tree without `--apply` + explicit confirmation.

## Milestone 5 — Expansion: multi-cloud platform (DONE 2026-10-10)

**Capability**: Kubernetes/YAML, Helm, CloudFormation adapters; Azure + GCP
rule packs; supply-chain intelligence (feed from aegis-ingestion);
optional service API.

**Changes**: one adapter per framework (each → same IR, so rules/graph keep
working); provider-scoped rule packs; API is a thin layer over the core —
Postgres/Redis stay optional for local scans.

**Acceptance**: per-framework coverage measured against the benchmark corpus;
no regressions on Terraform; performance numbers published.

## Cross-cutting (all milestones)

- **Benchmarks**: versioned corpus (vuln lab + prod project + crafted fixtures)
  vs pinned Checkov/Trivy/KICS. No superiority claims until numbers prove it.
- **Release gates** (spec §15): `go test ./...`, `-race`, fuzz on parsers,
  `go vet`, license review, reproducible signed builds, deterministic output,
  secret-free logs, no benchmark regressions.
- **Go-only rule**: stdlib + reviewed Go modules only. No Python/Rust/Node
  runtime may hide in the build.

## Build order (next smallest steps)

1. Land M1 agents → `go build`, `go test ./...`, scan both Terraform projects.
2. Fix what the corpus differential reveals.
3. Benchmark harness skeleton + first Checkov comparison point.
4. M2 resolver spike on one hard case (module outputs).

## M1 verification (2026-10-10)

- `go build ./...`, `go vet ./...`, `gofmt` — clean
- `go test ./...` and `go test -race ./...` — all packages pass
- `vuln-three-tier`: 41 resources → 14 findings, exit 1
- `vpc-peering`: 11 resources → 0 findings (clean code stays quiet)
- `demo-vuln`: 6 resources → 8 findings
- SARIF 2.1.0 validated (7 rules, 14 results)
- Prebuilt binary: `aegis` (linux/amd64) at repo root

## M2 verification (2026-10-10)

- New `internal/semantics`: MergeModules, ResolveResources (var defaults,
  local chains with cycle detection, bounded depth 32), ExpandModules (local
  modules, input binding, maxDepth 2, cycle-safe). 16 tests.
- New `internal/adapter/planjson`: `terraform show -json` → IR, sensitive
  values redacted to unknown.
- `ir.Value` gained `Ref` (dotted reference path); adapter preserves refs
  inside composite literals as unknown containers.
- Corpus differential: vuln-three-tier 14 → 16 findings (both new are true
  positives — S3 SSE check enabled by var-resolved bucket name matching),
  vpc-peering 0 → 0, demo-vuln 8 → 8. No new false positives.
- Plan JSON E2E: open SG fires, hardened RDS stays quiet, password redacted.
- `go test -race ./...` all green; vet + gofmt clean.
- Left unknown for M3: data.*, each/count/self, module outputs,
  resource-to-resource refs, interpolation, conditionals, functions.

## M3 verification (2026-10-10)

- New `internal/graph`: nodes/edges from refs (dangling refs rejected, no
  invented edges), `PubliclyExposed` (SG ingress 0.0.0.0/0, SG association,
  publicly_accessible RDS). 21 tests.
- New rules 101-104 (all `ir.CrossResourceRule`, registered in DefaultRegistry):
  101 IAM role assumable by anyone (critical), 102 IAM admin policy (high),
  103 public RDS exposure path (high), 104 public S3 exfiltration path (critical).
  28 tests. `jsonencode()` over static args now evaluates (adapter) so policy
  documents are analyzable.
- Findings carry `Path []PathStep`; text report renders attack paths.
- Corpus: vuln-three-tier 16 → 20 (3 with paths, all verified true positives),
  vpc-peering 0 → 0, demo-vuln 8 → 12 (all on intended-vulnerable fixtures).
- `go test -race ./...` all 8 packages green; vet + gofmt clean.
- Known overlaps kept deliberately: 102/006, 103/011, 104/002+003 (path
  variants vs single-resource checks; dedupe is a later product decision).
- Left for later: Condition-scoped trust policies, cross-account trust,
  inline role policies for 102, NotPrincipal/NotAction nuances.

## M4 verification (2026-10-10)

- New `internal/remediation`: Edit/Patch/Fixer model, 8 fixers (001 S3 SSE
  block, 002 S3 private ACL, 007/008/011 RDS booleans, 009 EBS, 010
  CloudTrail, 012 S3 versioning). Judgment calls (003/004/005/006, 101-104)
  deliberately get no auto-fix. 24 tests.
- `ValidatePatch`: temp-copy → apply → re-scan; Fixed + NewFindings reported.
  Original tree never touched during validation.
- CLI: `aegis fix <dir> [--apply] [--rule=] [--format=]` — dry run by default
  (md5-verified no-op); --apply writes only patches with Fixed && no
  NewFindings; overlapping edits deferred with explanation; converges on
  re-run. `scan --fail-on=critical|high|medium|low` policy gates.
- `examples/github-actions/aegis.yml`: build → SARIF scan → upload-sarif.
- E2E on vuln-lab copy: 20 → 15 → 14 findings, zero new findings introduced;
  remaining 14 are judgment calls. Original tree untouched.
- `go test -race ./...` all green; vet + gofmt clean.

## M5 verification (2026-10-10)

- New `internal/adapter/manifests`: K8s YAML (multi-doc) + CloudFormation
  YAML/JSON → IR. CFN types normalize to aws_* (unmapped → cfn_*); explicit
  property mapping; intrinsics → param defaults / typed refs / unknown.
  yaml.v3 (pure Go).
- New packs: `internal/rules/k8s` (3: privileged, runAsRoot, privesc),
  `internal/rules/azure` (5: storage public/TLS, NSG open, SQL public, KV
  purge), `internal/rules/gcp` (4: GCS public IAM, firewall open, SQL
  backups, GKE authorized networks), `internal/rules/supplychain`
  (AEGIS-SC-001: advisory feed vs pinned provider versions, semver
  constraints with ~> support).
- `internal/advisories`: JSON feed load + Affected() matching.
- CLI: `--rules=aws,azure,gcp,k8s,supplychain,all` (default all),
  `--advisories=file`, `aegis serve [--addr]` (POST /v1/scan, GET /v1/health;
  32 MiB / 1000 files / 60s bounds; loopback default; no DB required).
- Terraform adapter: `Module.ProviderReqs` from required_providers.
- E2E: K8s privileged Deployment → K8S-001; CFN unencrypted bucket + open
  SG → AWS 001/004/012 through the SAME rules; Azure/GCP fixtures fire;
  advisory flags pinned 5.1.0 in <5.2.0 range; serve API returns findings.
- Regression: vuln-three-tier 20, vpc-peering 0, demo-vuln 12 (unchanged).
- Perf: 41-resource lab scans in ~11ms.
- `go test -race ./...`: all 15 packages green; vet + gofmt clean.
- Known gaps: Helm chart rendering (feed rendered manifests), CFN
  Conditions/Mappings, pod-level securityContext, ephemeralContainers,
  cross-account trust, YAML bomb mitigation relies on file-size caps.

## Demo + benchmarks (2026-10-10)

- `demo/vulnerable/`: 3-resource demo project; scan → 5 findings →
  `fix --apply` → converges 5 → 2 → 1 (open SG left as judgment call).
- `docs/BENCHMARKS.md`: aegis 0.1.0 vs trivy 0.74.0 on vuln-three-tier —
  20 findings in 0.038s vs 35 in 1.81s (median of 5). Counts not ranked;
  rule sets differ; speed gap is real on this corpus.

## Optimization round (2026-10-10)

- Coverage: 9 new rules (AEGIS-AWS-201–209) closing measured Trivy gaps.
  Vuln lab 20 → 27 findings; peering 0 → 2 (true positives: VPCs without
  flow logs). 38 AWS rules total (16+4+9+9 across the numbering).
- Speed: parallel parsing + parallel rule evaluation (bounded pools).
  Byte-identical output, deterministic, race-clean. Lab ~0.011s end-to-end.
- Benchmarks: high-severity parity vs Trivy 0.74.0 (16 vs 16) on the lab
  corpus; ~160x faster wall-clock. See docs/BENCHMARKS.md.

## Hardening round (2026-10-10, per external assessment)

- Rigorous benchmark (30 runs, p95, RSS, TP/FP/FN): 85x median speedup
  (corrected from 160x), 0 FPs, 2 gaps closed (002 bucket_acl, 204 launch
  template). Lab 27 -> 30 findings, 19 high.
- Graph: fixed 103 misattributed-SG fallback and placeholder evidence step.
  Paths now only name proven, attached resources.
- Remediation: fixed ValidatePatch corruption blind spot (ResourceMissing
  gate + diagnostics gate), 2 new regression tests.
- API: audited clean — loopback-only, no accidental remote bind path, all
  bounds verified live. No auth by design (documented).
