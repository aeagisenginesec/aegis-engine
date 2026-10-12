# Scaling Resolution — Phase 2, Final Superiority Mission

Date: 2026-10-12. Branch: `mission/final-superiority`. Engine: Go 1.25.4.

## The question

A prior audit reported "near-quadratic scaling past ~4k resources", while a
follow-up on HOMOGENEOUS workloads measured roughly linear behavior
(1k→0.17s, 2k→0.28s, 4k→0.73s, 8k→1.03s). Both claims were tested against
REFERENCE-DENSE workloads. Verdict: **the quadratic claim was real but
workload-specific — and on dense reference graphs it was actually ~cubic.
Four algorithmic defects were found and fixed. The engine now scales at
exponent ≈1.25 (least-squares, 1k–16k) on the same dense workloads.**

## Methodology

- Generator: `/tmp/scale-gen/gen.py` (kept out of the repo). Deterministic
  LCG; every resource references several others via interpolations.
- Workload mix per 20 resources: 8× `aws_security_group` (world-open ingress
  + 3 SG→SG refs + dynamic ingress block), 3× standalone
  `aws_security_group_rule`, 3× `aws_instance` (3 SG refs + instance-profile
  ref), 2× `aws_db_instance` (2 SG refs), 1× IAM role + 1× policy
  (`s3:*`/`ec2:*`/`iam:PassRole`) + 1× attachment + 1× instance profile;
  plus `aws_lb`/`aws_s3_bucket`/`aws_lambda_function` every 200 resources;
  `./modules/net` instantiated N/80 times (dynamic blocks, module input
  rewriting — the scanner expands modules). This stresses reference
  resolution, per-resource rule work, the reference-graph builder, and the
  attack-path/BFS builders simultaneously.
- Parsed resource counts: 1k→1059, 2k→2113, 4k→4218, 8k→8428, 16k→16848
  (includes module-expanded resources).
- Timing: `aegis scan <dir> --format=json` (stdout discarded), 5 runs per
  size, median reported. Machine: 2 vCPU, 7.7 GiB RAM (only ~280 MiB free
  during runs — memory-constrained), Linux.
- Profiling: Go pprof (CPU) via a temporary test harness (removed after use);
  generator and profiles live in `/tmp/scale-gen`, not in the repo.

## Before: super-quadratic confirmed (least-squares exponent ≈ 3.0)

| resources | median scan time (before) |
|----------:|--------------------------:|
|      1059 |                     3.30s |
|      2113 |                    24.27s |
|      4218 |                   217.20s |
|      8428 |        not measured (too slow) |
|     16848 |        not measured; cubic fit projects ~29 min |

Ratios: 7.35× and 8.95× per doubling → exponent ≈ 3.0. pprof on the 1k run
attributed **73.7% of CPU to `sgIngressSources`**
(`internal/rules/aws/attack_paths_multihop.go`, rule AEGIS-AWS-105): it
scanned ALL n resources to find standalone SG-rule resources targeting one
SG, and was called once per SG plus once per (EC2, RDS-SG) pair —
O(sgs·n + ec2s·rdss·n).

## Fixes (algorithmic — indexing / hoisting / single-pass, not caching)

All in `internal/rules/aws/attack_paths_multihop.go`,
`internal/rules/aws/attack_paths.go`, `internal/attackpath/killchain.go`.
No rule logic, thresholds, or output shapes changed.

1. **`sgRuleIndex`** — one O(n) pass indexes standalone
   `aws_security_group_rule` / `aws_vpc_security_group_ingress_rule`
   resources by the SG their `security_group_id` targets; `sgIngressSources`
   becomes an O(1) lookup. Same filters, same dedupe, same sort → identical
   output set.
2. **Kill-chain correlation de-duplication** (`internal/attackpath/killchain.go`)
   — `BuildKillChains` re-parsed `securityGroupsOf` per (data, workload,
   entry) triple (O(d·w·e) parses; pprof: 55% of the 8k run) and recomputed
   `entriesReaching` per (data, workload) pair. Now: per-resource SG sets
   precomputed once (O(n)), `entriesReaching` memoized per workload
   (it never depended on the data store).
3. **Per-SG ingress sources precomputed** — `sgIngressSources` parses a SG's
   own ingress blocks, so the EC2→RDS pair loop was re-parsing the same
   blocks per pair. `sgSources` map built once per `buildAttackGraph`.
4. **Single-source BFS** — `shortestAttackPath` ran a full BFS per RDS
   (O(rdss·(V+E)); pprof: 46% of the 16k run). Replaced by one BFS from
   `"internet"` (`bfsPrev`) + O(depth) path reconstruction per RDS.
   BFS explores deterministically, so each per-target run is a prefix of the
   full run and reconstructed paths are provably identical.
5. Minor hoists with identical semantics: `openSGs(resources)` out of the
   per-RDS closure in AEGIS-AWS-103 (was O(n) per public RDS);
   the `byAddr` index out of per-finding `multiHopFinding` (was O(n) per
   finding).

## After: exponent ≈ 1.25 (least-squares over 1k–16k)

| resources | findings | median scan time (after) | per-doubling | speedup vs before |
|----------:|---------:|-------------------------:|-------------:|------------------:|
|      1059 |     6814 |                    0.46s |          —   |              7.2× |
|      2113 |    14273 |                    1.01s |  2.20× (1.13)|               24× |
|      4218 |    29963 |                    2.08s |  2.06× (1.04)|              104× |
|      8428 |    65548 |                    5.51s |  2.65× (1.41)|                —  |
|     16848 |   151347 |                   15.00s |  2.72× (1.45)|    ~116× (projected) |

Least-squares fit over all five sizes: **exponent 1.25**.
Post-fix pprof (16k): no single redundant-recomputation hotspot remains —
`BuildKillChains` 40% (the d×w / w×e correlation joins over `HasEdge`,
small constants), `multiHopPath` 23% (pair loop, BFS, graph build), HCL
parsing 13% (linear, inherent).

## Verification

- **Completeness**: findings identical before→after at every fix stage —
  6814 findings on the 1k workload, byte-identical JSON (only
  `aegis_version`/`target` header fields normalized; the JSON carries no
  timestamps) after each of the 4 fixes, hence transitively identical from
  the original binary to the final one. No detection was reduced: no rule
  logic, thresholds, caps, or output shapes changed.
- **Determinism**: 3 repeated runs byte-identical (sha256) on the 1k
  workload and on the 16k workload (151,347 findings).
- **Tests**: `go test ./internal/rules/... ./internal/attackpath/
  ./internal/graph/` — all pass. No `*_test.go` files and nothing under
  `internal/qualitygate/` was modified by this work.

## Scope and limits of the claim (read before quoting)

- "≈linear" describes **engine correlation work** on reference-dense
  synthetic Terraform up to 16k resources / 151k findings, on a 2-vCPU,
  memory-constrained machine. Least-squares exponent 1.25; top-end pairwise
  exponents 1.41–1.45 (8k→16k).
- The residual top-end super-linearity is accounted for, not hand-waved:
  (a) **finding output volume** — on adversarially dense graphs the
  kill-chain rule legitimately emits a data×workload×entry cross-product
  (findings grow ~n^1.2 here: 6.8k→151k); serializing and constructing that
  output is inherently output-proportional and cannot be reduced without
  reducing detection; (b) the EC2↔RDS pair-correlation join
  (O(ec2s·rdss) with small constants), which is inherent to the rule's
  pair semantics.
- Production variance is expected: real estates differ in type mix and
  reference density. This workload is deliberately adversarial (every SG
  world-open, dense SG↔SG/EC2/RDS cross-references) — a worst case, not a
  typical case. Do not claim linear complexity beyond what was measured.
- The homogeneous-workload linear result from the earlier follow-up is
  consistent with these findings: sparse reference graphs never exercised
  the defective paths.

## Files changed (uncommitted, working tree)

- `internal/rules/aws/attack_paths_multihop.go` — sgRuleIndex, sgSources
  precompute, single-source BFS (bfsPrev/reconstructPath), byAddr hoist.
- `internal/rules/aws/attack_paths.go` — openSGs hoist in AEGIS-AWS-103.
- `internal/attackpath/killchain.go` — sgSets precompute, entriesReaching
  memoization, hoisted SG-set lookups.
- New: `docs/audit/SCALING_RESOLUTION.md` (this file).
