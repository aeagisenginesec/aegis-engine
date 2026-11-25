# v2.4.0 — IAM kill-chain links + attack-path remediation (SOC #16, IAM #19)

Branch: `feature/v240-killchain` (from `fa23c9f`, Phase B merged, 1,148 rules).
No merge, no push, no version bump. Rule count unchanged: 1,148.

## 1. What was built

### IAM-permission reachability in the attack-path graph builder

New file `internal/attackpath/iam_reach.go` (+ `iam_reach_test.go`).
`Builder.IAMReachLinks()` returns every evidence-backed IAM permission
link; `BuildKillChains()` wires them into AEGIS-AWS-629 chains, and the
refactored `findIAMChains()` (same resolution) feeds AEGIS-AWS-630.

A link exists only when all three are proven from the configuration in
scope — principal, grant, target — and every link carries its evidence
(policy statement actions + resource pattern, role/trust spans).

**Link class 1 — workload links.** A workload's assumed role (Lambda
`role`, EC2 instance-profile role) whose policy grants data-plane
actions on an in-scope data store. The grant must be **over-broad in at
least one dimension** — a service-wildcard action (`s3:*`, `*`) or a
wildcard resource (`*`, `arn:aws:s3:::*`). A fully-scoped grant (one
action on one ARN) is ordinary least-privilege use and creates no link.
Chain shape: `entry → workload → role → policy → [IAM-reachability hop
naming the grant and target] → data`. The IAM hop appears ONLY on
IAM-only bridges — network chains keep their exact existing hop shape.

**Link class 2 — open-trust links.** A role assumable by any AWS
principal (trust statement: Principal `*` / `{"AWS": "*"}`, Action
`sts:AssumeRole`, **no Condition**) whose policy grants data-plane
actions on an in-scope data store. Any data-plane grant counts, however
scoped — the openness is the broadness. Chain shape:
`internet (open trust) → role → policy → [IAM-reachability hop] → data`.
No workload compromise is needed, so these chains are Critical.

**Resolution surfaces.** Attachments (`aws_iam_role_policy_attachment`,
`aws_iam_policy_attachment` roles lists), inline `aws_iam_role_policy`,
and `managed_policy_arns` (`AdministratorAccess` only — other managed
ARNs are unknown content, never guessed). Roles resolve via reference,
plain name, or IAM ARN literal naming a role in scope; out-of-scope
roles link to nothing. `findIAMChains` (630) shares this resolution, so
630 now also fires for inline policies and managed AdministratorAccess
on workload roles.

**Data-plane matching.** Per-service representative actions: S3
(Get/Put/DeleteObject, ListBucket), DynamoDB (Get/Put/Delete/UpdateItem,
Query, Scan, Batch*), RDS (`rds-db:connect`, `rds-data:*`).
`rds:*` deliberately does NOT match `rds-db:connect` (different IAM
prefix). Control-plane actions (`Describe*`, `PutBucketPolicy`, …) never
match. Resource patterns glob-match the target's canonical ARNs
(segment-wise; region/account are wildcards because Terraform does not
state them); a grant naming an ARN outside the scope links to nothing.
`NotAction`/`NotResource` statements are skipped (same documented blind
spot as `rules/aws` — negative logic needs full policy evaluation).
Unparseable/unknown policy documents yield no links.

**Deliberately NOT modeled.** Inline `inline_policy` blocks on
`aws_iam_role`; ECS task roles (service → task definition → role is
indirect); transitive assume-role chains (A assumes B which reads the
bucket); DynamoDB GSI-level resource ARNs.

**Duplicate-address guard (found by measurement, §2).** IAM resolution
uses a deduped-by-address resource view (first wins, stable sort), the
same view the graph already uses. Two files declaring one address must
never merge attributes across copies.

## 2. False-positive measurement

Baseline (branch base `fa23c9f`, binary `/tmp/aegis-baseline`):
`go test ./...` 32 packages, 0 FAIL; `doctor` 1,148 rules;
quality-gate PASS (precision 100% tp=355 fp=0 fn=0, recall 100%,
rule-coverage 363/363, p95 289.0ms, parser-safety 15/15).

After the change (binary `/tmp/aegis-killchain`):

| Check | Result |
|---|---|
| `go test ./...` | 32 packages, 0 FAIL (exit 0) |
| `go vet ./...` | clean |
| `gofmt` | clean on all touched files (one pre-existing unformatted file, `internal/rules/aws/security_groups.go`, untouched) |
| `aegis doctor` | all checks passed, 1,148 rules |
| quality-gate precision / recall / rule-coverage / parser-safety | PASS — precision 100.0% (tp=355 fp=0 fn=0), recall 100.0%, 363/363, 15/15 |
| quality-gate performance | **see note below** |
| Regression fixtures 104/105/629 (vuln + secure) | byte-identical finding sets (rule/resource/severity) |
| Demo `secure/` whole-dir scan | identical (132 findings) |
| Demo `vulnerable/` whole-dir scan | identical (176 findings) **after the dedup guard** |
| New positive E2E fixtures | Lambda `s3:*` on `*` → 629 Medium + 630 High; open-trust role + scoped `s3:GetObject` → 629 Critical — all with IAM-reachability hops and evidence |

**Two findings the measurement caught and killed.**

1. *Frankenstein role (FP, fixed).* First demo-diff run showed 2 new
   Critical 629s on the whole-dir demo scan. Root cause: two scenario
   files both declare `aws_iam_role.demo` — open trust in `09`, managed
   AdministratorAccess in `10`. IAM resolution iterated all resources
   and merged trust from one copy with the policy from the other into a
   role that exists in neither file. Fix: deduped-by-address view +
   stable sort in `dedupedResources()`; pinned by
   `TestIAMReach_NoLinkDuplicateRoleAddress`. After the fix the demo
   diff is zero. (The finding would have been a true positive for a
   real single stack with that shape — but the demo's scenarios are
   independent stacks, so merging them is unsound.)

2. *Performance gate (noise, not a regression — needs a quiet re-run).*
   One quality-gate run on this branch reported p95 502.1ms vs the
   500ms threshold (baseline 289.0ms). That run executed while sibling
   feature agents were saturating the box (load average 6.6–9.1 on
   1.5 shared CPUs: another agent's quality-gate + a Checkov held-out
   run at 100% CPU). Precision/recall/coverage/parser-safety on the
   same run were all PASS with identical metrics to baseline
   (tp=355 fp=0 fn=0). A second gate attempt on the final binary ran
   10+ minutes without finishing under load ~4–6 (a sibling Checkov
   run still at 65% CPU) and was killed — the gate is unusable while
   the box is this contended. Direct evidence instead: interleaved
   A/B scans of the demo vulnerable dir (5 rounds each, final binary):
   baseline median 73ms (runs 65–74ms), killchain median 26ms (runs
   23–46ms) — no slowdown demonstrated on this workload. Mitigations
   landed anyway: the glob matcher is now a linear scan instead of a
   per-call regexp compile, role-name resolution uses a precomputed
   index, and role/policy resolution is cached per Builder instead of
   recomputed. The performance gate must be re-run on a quiet machine
   before release; the numbers above do not support attributing the
   502ms to this change.

**Gating decision.** No link class was gated off: after the dedup fix,
every measured corpus shows zero new findings except the deliberate
positive fixtures. The over-broad gate on workload links (scoped grants
create no link) is the narrowness that keeps this true.

## 3. Remediation consistency (SOC #16)

`internal/rules/remediation.go` — content pass only; rule IDs and
severities unchanged. 103, 105, 630 had no detailed entry (generic
fallback); 104 cross-referenced other rules' fixes (`see AEGIS-AWS-003
fix`); 629 was correct but IAM-blind.

| Rule | Before | After |
|---|---|---|
| 103 Public RDS exposure path | Generic AWS fallback ("Review the flagged configuration…") | Ordered: `publicly_accessible = false` + private subnets → remove `0.0.0.0/0` from the named SG → audit CloudTrail/DB logs, rotate creds → rescan |
| 104 Public S3 exfiltration path | "Break the public exfiltration path. Make the bucket private (see 003 fix), remove the policy (see 006 fix)…" — pointers, no steps | Ordered CONTAIN → AUDIT → RECOVER → VERIFY: all four public-access-block settings, delete the `Principal "*"` `s3:GetObject` statement (or set ACL `private`), CloudTrail + S3 access-log audit, rotate exposed secrets |
| 105 Multi-hop network attack path | Generic AWS fallback | Hop-by-hop: close entry SG → break the SG-to-SG trust (remove source-SG ingress) → isolate the EC2 stepping stone (remove shared SG, IMDSv2, patch, assume compromise) → RDS private → flow-log/CloudTrail audit → rescan |
| 629 Full kill chain | "Break the kill chain at the cheapest hop" (network-only order) | Same cheapest-hop structure, now branched: network bridge → close entry; **IAM bridge → scope the named policy first** (replace `s3:*`/`*`, remove `AdministratorAccess` from workload roles); + CloudTrail audit for the role's data-plane calls before closing |
| 630 IAM privilege chain | Generic IAM fallback ("Apply least privilege…") | Ordered: read the granted actions from the path → replace wildcard/sensitive actions with exact ARNs → split `PassRole`/`AssumeRole` into a human-gated deploy role → verify with Access Analyzer → audit past use |

Pinned by `TestRemediationFor_AttackPathEntries` (key phrases per rule,
plus guards: no generic-fallback text, no `see AEGIS-AWS-*` pointers).
Regression fixtures (`expected.json` pins rule-ID lists only) needed no
updates; remediation text is not pinned by any golden file.

## 4. Tests

- `internal/attackpath/iam_reach_test.go` (new, 20 tests): positives —
  `s3:*` on `*`, scoped action on named bucket (links only that
  bucket), `s3:GetObject` on `*`, DynamoDB table ARN, inline policy,
  managed AdministratorAccess, open trust with a scoped grant,
  open-trust admin; negatives — scoped workload grant, out-of-scope
  ARN, `NotAction`, Deny-only, control-plane-only action, unknown
  (variable) policy, no data store, unattached role, conditioned trust,
  service-principal trust, out-of-scope role ARN, duplicate role
  address; plus network-chain shape unchanged, parser matching matrix,
  determinism.
- `internal/rules/aws/attack_paths_killchain_test.go` (+4 tests):
  IAM-only 629 (Medium, UNCERTAIN entry, IAM hop present), open-trust
  629 (Critical), scoped-grant quiet, conditioned-trust quiet.
- `internal/rules/remediation_test.go`:
  `TestRemediationFor_AttackPathEntries`.

## 5. Left out (with reasons)

- `inline_policy` blocks on `aws_iam_role` and ECS task roles: real
  surfaces, but each is a new resolution path with its own FP surface;
  the three covered surfaces (attachments, inline policy resources,
  `managed_policy_arns`) cover the common shapes. Follow-up, not a gap
  in the measured behavior.
- Transitive assume-role reachability and GSI-level ARNs: see §1.
- No new rule ID: the feature surfaces through 629/630, so the rule
  count stays 1,148 and no registry/doc/coverage churn was needed.
- No CHANGELOG entry: parallel feature branches are editing it; the
  release lead should fold this in at merge time.
