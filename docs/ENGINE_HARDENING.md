# Aegis Engine Hardening — Workstream B

Date: 2026-10-12. Scope: the AWS analysis engine — Terraform adapter
unknown-value handling, AWS rule unknown/missing semantics, diagnostics
visibility, span preservation, graph traversal safety, output determinism,
and parser failure visibility.

Verification (all green after the fixes):
`go build ./...` · `go vet ./...` · `gofmt -l .` clean · `go test ./...` green ·
`aegis quality-gate` **PASS** (precision 100.0% ≥ 95%, recall 100.0% ≥ 90%,
216/216 critical/high rules tested, perf p95 31.4ms ≤ 500ms, parser-safety
15/15). Rule count unchanged: **286 AWS rules**, none removed or disabled.

---

## 1. Unknown-value audit

### 1.1 Adapter (`internal/adapter/terraform/terraform.go`)

Reviewed every path by which an expression becomes an `ir.Value`:

- `valueFromExpr`: only pure static literals (`staticExpr` whitelist:
  literals, single-part templates, tuples/objects of statics, unary minus
  on numbers) become `Known=true`. Everything else → `refOrPartial` or
  plain `ir.UnknownValue(span)`.
- References (`var.*`, `local.*`, `data.*`, `each.*`, `count.*`, `self`,
  `module.*`, resource traversals) → `Known=false` with `Ref` set to the
  dotted path (`traversalRef`). Tuples/objects mixing statics and refs
  become **unknown containers** preserving inner refs for the semantics
  layer — never zero-values.
- Function calls: only `jsonencode()` over a fully static argument is
  evaluated (whitelisted, no code execution); all other calls → unknown.
- `ctyToValue`: null, unknown, or unrecognized cty types → unknown.
- A `recover()` guard converts any evaluation panic into unknown.
- `attributesFromBody`: nested blocks become `[]ir.Value` of
  `map[string]ir.Value`; repeated blocks append; attribute/block name
  collision resolves deterministically (block wins).

**Result: no silent drops or zero-value substitutions found.** Every
unresolved construct is explicit `Known=false`.

### 1.2 Rules (`internal/rules/aws/*.go`)

Method: harvested all 181 attribute names read by AWS rules (helper calls
plus direct `Attributes[...]`/`.Attr(...)` reads) and all 146 resource
types rules apply to (including companion types only referenced inside
`CheckAll`). Classified every absent→pass and unknown-handling site.

The package contract (helpers.go): **present-but-unknown → "cannot
decide" → no finding**; **absent → evaluated against the provider's
documented default** (fail closed when the default is insecure). Direct
`.Raw` reads (13 sites) were all already guarded by `Known` checks.

**77 absent→pass sites reviewed: 69 correct** (secure provider default,
e.g. `publicly_accessible` defaults false, `acl` defaults private,
`max_session_duration` defaults 1h; or the attribute is Required so
absence means invalid config, e.g. `aws_iam_policy.policy`), **8 bugs
fixed** — absent was silently treated as secure although the provider
default is insecure. Each fix fires with evidence
`Actual: "absent (provider default: X)"` via the new
`absentInsecureDefault` helper (internal/rules/aws/helpers.go):

| Rule | File:line | Attribute | Insecure default that was silently passed |
|------|-----------|-----------|------------------------------------------|
| AEGIS-AWS-404 | edge2.go:188 | `aws_apigatewayv2_route.authorization_type` | API default `NONE` → publicly invocable |
| AEGIS-AWS-407 | edge2.go:327 | `aws_lambda_function_url.authorization_type` | API default `NONE` → public HTTPS endpoint |
| AEGIS-AWS-419 | data2.go:402 | `aws_athena_workgroup.enforce_workgroup_configuration` | default `false` |
| AEGIS-AWS-427 | identity2.go:338 | `aws_sagemaker_notebook_instance.direct_internet_access` | API default `Enabled` (verified against provider docs) |
| AEGIS-AWS-357 | databases2.go:292 | `aws_dms_endpoint.ssl_mode` | default `"none"` → plaintext (verified) |
| AEGIS-AWS-509 | network_exposure.go:236 | `aws_transfer_server.endpoint_type` | API default `PUBLIC` |
| AEGIS-AWS-557 | coveragegaps.go:319 | `aws_vpc_endpoint.policy` | default policy allows full access |
| AEGIS-AWS-324 | network.go:116 | `aws_lb_listener.ssl_policy` (HTTPS/TLS) | AWS applies `ELBSecurityPolicy-2016-08`, weak by this rule's own definition |

**5 rules fired on present-but-unknown values** (`if !present || !known
|| len(blks) == 0 { fire }`) — fixed to return nil on unknown:

- AEGIS-AWS-445 (checkov_parity.go:250) — unknown `logging` block
- AEGIS-AWS-637/638/639/640 (es2.go) — unknown `domain_endpoint_options` /
  `cluster_config` / `advanced_security_options` blocks

**9 cross-resource rules fired "companion missing" while a companion
existed with an unresolvable link** (e.g. a public-access-block with
`bucket = var.x` was ignored, then every bucket was reported "absent").
New `companionLinkUncertain` helper (helpers.go): if any companion's link
is present-but-unknown or an unresolvable ref, parents without *proven*
coverage are undecidable → no finding. Fixed:

- AEGIS-AWS-206 (S3 public access block), 209 (VPC flow logs),
  443 (S3 SecureTransport policy), 445 (S3 access logging),
  513 (AppSync WAF), 558 (S3 Object Lock), 559 (S3 inventory),
  602 (S3 notifications), 613 (WAFv2 logging)

Deliberately **not** changed: 4 structural rules that fire on resource
existence alone (the type itself is the finding — no attribute values
involved): 309 (deprecated launch configuration), 396 (default VPC),
400 (default subnet), 556 (TGW propagation).

### 1.3 Regression net: `unknown_never_fires_test.go`

New property test (`internal/rules/aws/unknown_never_fires_test.go`):
for **every one of the 286 AWS rules × every applicable resource type**,
a resource with all 181 attributes present-but-unknown must yield zero
findings from `Check`; a companion-inclusive variant asserts the same for
every `CrossResourceRule.CheckAll`. The 4 structural rules are allowlisted
with rationale. This test caught all 14 unknown-handling bugs above
before they were fixed.

---

## 2. Explicit unknowns (adapter diagnostics)

New warnings (Level `warning`, with source span) so analysis gaps are
visible instead of silent:

- `dynamic` blocks: `terraform: dynamic "ingress" block is not expanded;
  its nested configuration is not analyzed` (terraform.go,
  `attributesFromBody`). The block is still kept verbatim under the
  `"dynamic"` key; rules just can't see inside it.
- `count` / `for_each` with unresolvable expressions:
  `terraform: aws_instance.web uses "count" with an unresolvable
  expression; analyzed as a single instance` (`resourceFromBlock`).
  Static values stay silent.

CLI surfacing verified: diagnostics were already wired into both outputs
(`internal/report/report.go`); text output now also prints `file:line`
per diagnostic (previously message only). End-to-end check on a fixture
with a dynamic block + `count = var.n`: both warnings appear in text
(`diagnostics: 2` with locations) and in JSON (`diagnostics[]` with full
spans).

---

## 3. Source location preservation (10/10)

Fixture `/tmp/spancheck/main.tf` (since removed; recipe in §3 of the
workstream notes) with 10 violations across 10 rules. Chain traced:
source line → adapter `Span` → `Resource.Attributes` span →
`Finding.Evidence.Span` → CLI text and JSON. All 10 correct:

| Rule | Attribute present? | Evidence line | Source |
|------|-------------------|---------------|--------|
| 002 S3 public ACL | yes (`acl`) | 3 | attr line |
| 004 SG open ingress | yes (`cidr_blocks`) | 11 | attr line |
| 006 IAM admin policy | yes (`policy`) | 22 | attr line |
| 007 RDS unencrypted | no | 15 | resource block start |
| 009 EBS unencrypted | yes (`encrypted`) | 36 | attr line |
| 010 CloudTrail validation | yes | 40 | attr line |
| 201 LB internet-facing | no (`internal`) | 25 | resource block start |
| 357 DMS no SSL | no (`ssl_mode`) | 43 | resource block start |
| 407 Lambda URL no auth | no (`authorization_type`) | 29 | resource block start |
| 419 Athena not enforced | no | 49 | resource block start |

Absent attributes fall back to the resource block's start line via
`evidenceSpan`; file paths are unmangled in both outputs. No breaks.

---

## 4. Graph traversal safety

New `internal/graph/graph_safety_test.go` (`package graph_test`, avoids an
import cycle with `rules/aws`):

- **Cycle test**: A→B→C→A reference cycle + open SG. Asserts the cycle
  edges exist (test is meaningful), then runs `graph.Build`,
  `PubliclyExposed`/`OutEdges`/`InEdges` per node,
  `attackpath.Builder.BuildKillChains`/`IAMChains`, every AWS
  `CrossResourceRule.CheckAll`, and full `Registry.Run` under a 30s
  watchdog. Terminates instantly, no panic, no duplicate findings.
- **10k-node test**: 10k `aws_instance` chain + open SG + DB. Same
  traversal battery: **2.2s**, 2 findings, no panic, no duplicates.

Duplicate definition: same RuleID + resource + evidence attribute +
actual + span emitted twice by one rule → none found. (Code review:
multihop BFS uses a visited set + depth cap 4; killchain builder uses
`HasEdge` only, no transitive recursion; `PubliclyExposed` recursion is
depth ≤ 2; `dedupeChains` keys chains.)

---

## 5. Determinism

`aegis scan --format=json ~/workspace/terraform/vuln-200/` run **10
times**; sha256 of each raw stdout:

```
f6840ed1f834a1433941d861b01fd631191fdd0b9f01269d30156e2628b66b02  (×10)
```

All 10 identical. The JSON envelope carries no timestamp
(`aegis_version`, `target`, `resources_scanned`, `findings`,
`diagnostics`), so no normalization was needed. Determinism sources
already in place and now proven: sorted rule registry, sorted finding
order (rule → resource → attribute), sorted graph nodes/edges, sorted
resource discovery. Current vuln-200 result: **855 findings / 201
resources / 0 diagnostics** (the fail-closed fixes in §1.2 contribute a
net +6 on this corpus: 419×2, 427×2, 509×2; the remainder of the delta
vs the 2026-10-11 figure of 451 comes from rules added since, not from
this workstream).

---

## 6. Parser failure visibility

`internal/qualitygate/parser.go` probes extended **9 → 15**:

- new: `null-bytes`, `utf16-bom`, `deep-nesting-60` (balanced 60-level
  nesting vs `MaxNestingDepth = 50`), `unbalanced-extra-close`,
  `truncated-mid-list`; new `whitespace-only` wantClean case.
- Invariant (unchanged): non-empty garbage must produce an error or a
  diagnostic — never "0 findings, clean". `TestParserProbes` fails the
  build otherwise.

End-to-end CLI verification (each in its own directory): truncated HCL,
binary garbage, null bytes, 60-level nesting, unbalanced braces → all
produce `resources: 0, findings: 0, diagnostics: 1` with a Level `error`
diagnostic naming the file and cause (via `PreValidate` + `safeParse`
wrapping). `aegis quality-gate` parser-safety: **15/15 explicit**.

---

## Unknown-value policy (as implemented)

1. **Unknown (present, unresolvable)** → "cannot decide" → the rule
   emits **no finding**. Never treated as secure *or* insecure.
2. **Absent** → evaluated against the provider's documented default.
   Insecure default → finding fires naming the default
   (`absentInsecureDefault`); secure default or Required attribute →
   no finding.
3. **Unmodelable constructs** (dynamic blocks, unknown count/for_each)
   → `warning` diagnostic with span, surfaced in text and JSON output.
4. **Unresolvable cross-resource links** → "companion missing" findings
   are undecidable while an unlinkable companion exists
   (`companionLinkUncertain`).

## Files changed

- `internal/rules/aws/helpers.go` — `absentInsecureDefault`,
  `companionLinkUncertain`
- `internal/rules/aws/{edge2,data2,identity2,databases2,network_exposure,coveragegaps,network,checkov_parity,es2,coverage2,hygiene}.go` — 21 rule IDs fixed
- `internal/rules/aws/unknown_never_fires_test.go` — new property test
- `internal/rules/aws/{edge2,data2,identity2,databases2,network_exposure,network,coveragegaps}_test.go` — 7 new absent-fires tests; 324/509/357 expectations updated
- `internal/adapter/terraform/terraform.go` — dynamic-block + count/for_each warnings
- `internal/adapter/terraform/terraform_test.go` — 3 new tests
- `internal/report/report.go` — diagnostic locations in text output
- `internal/graph/graph_safety_test.go` — new cycle + 10k-node tests
- `internal/qualitygate/parser.go`, `qualitygate_test.go` — 15 probes
