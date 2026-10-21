# 25 — Sprint 2: False-Positive Family Hunt (R4)

Date: 2026-10-20 · Branch: `mission/gap-userdata-eol-image` · Engine HEAD at start: Sprint-1 close (`d0eda66`)

## Mission and method

Sprint 1 closed the R4 blind evaluation at TP 136/136, FN 0. The
post-Sprint-1 sweep's findings contain 2,227 "FP candidates"
(findings matching no ground-truth concept, score.py machinery,
hygiene exclusions applied). This sprint adjudicated those candidates
family by family and killed every genuine false-positive family at the
mechanism level, without regressing recall.

Method: candidates recomputed with score.py's own machinery; every
family with ≥10 candidates and every critical/high candidate was
adjudicated by reading the corpus source at the firing resources
(≥5 firings sampled per family, all if fewer; the uniform Azure blocks
sampled across projects). Where duplication was suspected, verdicts
were decided by comparing the rules' firing truth tables in code, not
by corpus overlap alone. The frozen run's adjudication
(`labels/fp-adjudicated-aegis.json`: 2,029 TP / 279 HYGIENE / 0 factual
FP) was treated as a prior and re-verified, not as truth.

## Headline result

| Metric | Before | After |
|---|---|---|
| Sweep findings (raw) | 2,417 | 2,234 (−183) |
| TP | 136 | **136** |
| FN | 0 | **0** |
| FP candidates | 2,227 | 2,044 (−183) |
| Registered rules | 1,155 | 1,140 |

(The 2,364 findings figure quoted at mission start is the raw 2,417
minus the 53 findings of HYGIENE_RULE_IDS rules, which score.py
excludes before counting.)

Verdicts over all 2,227 candidates (full record:
`labels/fp-adjudicated-sprint2.json`): **TP 2,065 · NOISE 142 ·
FACTUAL-FP 20**. No factual-FP family was found among the
absence-based Azure/K8S/AWS blocks, the criticals, or the long tail —
every sampled firing in those families is a real weakness (explicit
insecure value, or absence where the platform default is the insecure
state). The genuine FP mechanisms were: **(1) duplicate rules**
reporting one weakness two or three times, and **(2) image-metadata
rules firing on discarded Docker build stages**.

## Kills

### A. Duplicate rules deprecated (15) — mechanism: later "round" files re-implemented existing checks

Each removal follows the repo's deprecation protocol (pack
unregistration + `deprecatedRuleIDs` entry in
`internal/rules/ruleidcheck.go` + `docs/audit/DEPRECATED_RULE_IDS.md`
+ registry/pack/compliance test updates). Canonical rules were
verified to still fire on every affected target (see collateral check).

| Removed | Canonical | Why (truth-table comparison) | Candidates killed |
|---|---|---|---|
| AEGIS-AZURE-191 | AEGIS-AZURE-031 | Exact duplicate: same attribute (`shared_access_key_enabled`), same table, same severity | 52 |
| AEGIS-AZURE-007 | AEGIS-AZURE-187 | Strict subset: 007 fires on ACLs absent or `default_action="Allow"`; 187 fires on absent or any ≠ `"Deny"`, all blocks | 39 |
| AEGIS-AWS-540 | AEGIS-AWS-311 | Identical firing sets (28/28) at High vs Medium; 540's engine scoping ported into 311 (below) | 28 |
| AEGIS-AZURE-119 | AEGIS-AZURE-122 | Subset + FP-prone: identical to 122 when `allow_nested_items_to_be_public` is absent; its nested-present path fires even with `allow_blob_public_access = false`, where exposure is impossible — the bug class fixed in AZURE-195 during R5, never applied to 119 | 17 |
| AEGIS-AZURE-027 | AEGIS-AZURE-121 | Strict subset: 121 = 027 + the absent case (`min_tls_version` defaults to TLS1_0) | 6 |
| AEGIS-AWS-547 | AEGIS-AWS-308 | Exact duplicate truth table (Lambda `tracing_config`) | 4 |
| AEGIS-AZURE-075 | AEGIS-AZURE-229 | Strict subset: 229 checks all profile blocks and fires on empty `authorized_ip_ranges`; 075 went silent there | 3 |
| AEGIS-AZURE-230 | AEGIS-AZURE-128 | Strict subset: 230 fires only when the AAD RBAC block is absent; 128 also fires on `managed` absent/false | 3 |
| AEGIS-AZURE-245 | AEGIS-AZURE-127 | Exact duplicate truth table (`local_account_disabled`) | 3 |
| AEGIS-GCP-048 | AEGIS-GCP-109 | Strict subset: 048 is block-absent only; 109 also fires on `enabled=false`/missing `evaluation_mode` | 2 |
| AEGIS-GCP-010 | AEGIS-GCP-111 | Strict subset: 111 also fires when `enabled` is absent inside the block. Surviving severity is Medium (010 was High) — noted, accepted per the GCP-122 precedent | 2 |
| AEGIS-AWS-418 | AEGIS-AWS-523 | Subset of 523 (see below) | 1 |
| AEGIS-AWS-811 | AEGIS-AWS-523 | Exact duplicate of 523 at High vs Medium — one corpus OpenSearch domain was reported **three times** by 418+811+523 for a single missing control | 1 |
| AEGIS-AWS-812 | AEGIS-AWS-623 | Duplicate on `aws_opensearch_domain`; 623 also covers `aws_elasticsearch_domain` | 1 |
| AEGIS-AWS-840 | AEGIS-AWS-329 | Strict subset: 840 matched protocol case-sensitively; 329 uses EqualFold and covers more shapes | 1 |

Severity note: where duplicates disagreed (540 High vs 311 Medium,
811 High vs 523 Medium), the earlier canonical rule and its severity
were kept, following the repo's own GCP-122 precedent (duplicate High
removed, Medium canonical kept). No TP depended on the removed copies:
rescore held at TP 136 / FN 0.

### B. AWS-311 hardened with engine scoping (latent factual FP closed)

`rdsNoIAMAuth` fired on **every** `aws_db_instance` with IAM auth
absent/false, including engines where IAM database authentication
does not exist (Oracle, SQL Server) — a factual FP mechanism, and the
reason the scoped duplicate 540 was written in the first place. 311
now carries 540's scoping (files: `internal/rules/aws/storage.go`):
fires only for mysql/postgres/mariadb engine families (incl. version
suffixes); silent for aurora engines (covered by the
`aws_rds_cluster` rules) and when the engine is unknown. Twin tests:
`Test311_EngineScope` + the existing 311 twins re-based on a scoped
engine. Corpus behavior unchanged (all 28 corpus instances are
mysql/postgres — count identical before/after).

### C. DOCKER-017 / DOCKER-018 tightened to the final stage (20 factual FPs killed)

Both rules (maintainer label, STOPSIGNAL — image-config metadata)
fired on **every** stage of a multi-stage Dockerfile, including build
stages whose metadata is discarded and never ships (e.g. a
`golang` build stage in corpus project r4121). Those 20 candidates
(10 per rule) were factual FPs. Both rules now carry the
`is_final_stage` gate already used by `noNonRootUser` (DOCKER-002)
and `buildToolsInFinal` in the same pack: skip only when the stage is
known to be non-final. Files: `internal/rules/docker/docker_extra.go`;
twin test `Test017_018_FinalStageOnly` drives a real two-stage
Dockerfile through the adapter (build stage silent, final stage
fires). Candidates 40 → 30 per rule; the surviving 30 each are NOISE
(true of the final image, no security consequence, Low) and kept —
see noise decisions. The parity fixture `docker-multistage`
independently confirms the fix: 017/018 counts 2 → 1.

## NOISE decisions (tighten vs demote vs keep)

Chosen per family; all are factually true, so removal is never right —
the question is severity/scope.

- **DOCKER-017/018**: *tightened* (final-stage scope, §C) — the only
  noise family with a factual-FP edge. Kept at Low for final stages.
- **AWS-604** (SG/rule without description, 51), **AWS-672** (IAM
  user no tags, 14), **AWS-673** (IAM role no description, 3),
  **AWS-677** (policy statement no Sid, 3), **DOCKER-015** (no
  WORKDIR, 11): *kept unchanged*. All already sit at Low, the engine's
  floor — demotion is impossible — and they belong to the intentional
  Checkov-parity hygiene pack (several are even prefixed "Hygiene:"
  in their own descriptions, e.g. the finalgaps2 pack). Removing them
  would diverge from the pack's stated design for zero precision gain
  in this evaluation (score.py already excludes the worst offenders
  via HYGIENE_RULE_IDS; these were below that bar).

## Explicit adjudication: AZURE-263 absence policy

Flagged for review because AZURE-263 fires when
`publicNetworkAccess` is **absent**. Verdict: **the policy is
correct; no change.** Evidence: (1) all 4 candidate firings in the
sweep are on resources with an *explicit* `publicNetworkAccess:
"Enabled"` in corpus source — the absence path did not even produce
candidates here; (2) the rule's premise is documented platform
behavior: Cosmos DB defaults `publicNetworkAccess` to Enabled when
unset, so an absent attribute *is* the exposed state. Absence-fires
is the correct semantics for this control, as it is for the Azure
storage block (defaults verified the same way at sampled firings).

## HYGIENE_RULE_IDS audit (score.py's 9 exclusions)

Question per rule: does the exclusion hide a fixable FP family?

| Rule | Firings in R4 sweep | Verdict |
|---|---|---|
| AEGIS-AWS-706 (RDS default option group) | 28 | Legitimate noise: factually true (default option group attached), no FP mechanism. Exclusion justified. |
| AEGIS-AWS-699 (Nitro Enclaves not enabled) | 22 | Legitimate noise: absence is the norm (niche feature); claim true. Exclusion justified. |
| AEGIS-GCP-114 (GKE no release channel) | 2 | Legitimate noise: claim true. Exclusion justified. |
| AEGIS-AWS-798 (KMS policy statement no Sid) | 1 | Legitimate noise, same class as scored AWS-677 (kept Low). Note: 677 is scored while its twin 798 is excluded — an eval-side inconsistency, not an engine FP. |
| AEGIS-AZURE-111 (App Service detailed errors) | 0 | Nothing hidden: no firings in this corpus. Rule is ordinary logging hygiene. |
| AEGIS-GCP-215 (firewall no description) | 0 | Nothing hidden: no firings. Same documentation-hygiene class as AWS-604. |
| AEGIS-TF-004 (terraform version unpinned) | 0 | Nothing hidden: no firings. |
| AEGIS-AWS-658 (IAM role inline policy) | 0 | Nothing hidden: no firings (corpus roles use managed policies). |
| AEGIS-AWS-684 | 0 | **Rule no longer exists** — already in `deprecatedRuleIDs` (→ AEGIS-AWS-565). The exclusion is vestigial; it hides nothing. |

Conclusion: no fixable FP family hides behind the hygiene list. All
firing hygiene rules are factually accurate; the exclusions encode
"true but low-consequence", which is what the mechanism is for.

## Also verified clean (sampled, no change)

- **Criticals**: AWS-501/502 (privilege-escalation pairs on
  `Action="*"` policies), AWS-104 (public-read ACL) — all real in
  corpus source.
- **Uniform-52 Azure storage block** (028/029/032/033/034/125/147/181/
  192 + killed 191): corpus storage accounts are bare
  `azurerm_storage_account` resources; every absence claim is the
  insecure platform default. AZURE-124's cross-resource private-
  endpoint check is genuine (zero `private_endpoint` resources exist
  in the corpus); AZURE-148/149 verified above/in labels.
- **AWS-607 is not a subset of AWS-543**: 607 is content-aware
  (`"postgresql"` ∈ log exports), unique coverage — kept.
- **GCP-047 vs GCP-108**: distinct controls; 108's extra silence when
  `GKE_METADATA` is set is a correctness refinement, not a duplicate.
- **AWS-201 vs 506, AWS-618 vs 642**: distinct (different resources /
  log types) — not duplicates.
- **K8S-031**: selector matching is a real cross-resource computation;
  firings verified against the manifests.
- Zero-firing near-duplicates (AZURE-006/021/120/144/196/199) need no
  action in this evaluation; several are already deprecated.

## Priority family table (≥10 candidates, plus all critical/high families)

Verdicts: TP = real weakness, leave untouched · NOISE = true, no
security consequence · killed = TP content double-reported by a rule
deprecated in §A (counted TP in the labels file).

| Rule | Candidates | Severity mix | Verdict | Title |
|---|---|---|---|---|
| K8S-031 | 54 | medium:54 | TP | Workload without a NetworkPolicy |
| K8S-032 | 54 | medium:54 | TP | Container image without digest pin |
| AZURE-028 | 52 | medium:52 | TP | Storage account without blob versioning |
| AZURE-029 | 52 | medium:52 | TP | Storage account without blob soft delete |
| AZURE-031 | 52 | medium:52 | TP | Storage account allows shared key access |
| AZURE-032 | 52 | medium:52 | TP | Storage account without infrastructure encryption |
| AZURE-033 | 52 | low:52 | TP | Storage account without customer-managed key |
| AZURE-034 | 52 | low:52 | TP | Storage account queue without logging |
| AZURE-124 | 52 | medium:52 | TP | Storage account without private endpoint |
| AZURE-125 | 52 | low:52 | TP | Storage account without SAS expiry policy |
| AZURE-147 | 52 | low:52 | TP | Storage account without blob change feed |
| AZURE-148 | 52 | high:52 | TP | Storage account with public network access (default) |
| AZURE-149 | 52 | medium:52 | TP | Storage account without network rules |
| AZURE-181 | 52 | medium:52 | TP | Storage account without managed identity |
| AZURE-191 | 52 | medium:52 | TP | Storage account with shared key access enabled |
| AZURE-192 | 52 | medium:52 | TP | Storage account not defaulting to OAuth authentication |
| AWS-604 | 51 | low:51 | NOISE | Security group or rule without description |
| DOCKER-017 | 40 | low:40 | FACTUAL-FP×10/NOISE×30 | No maintainer label |
| DOCKER-018 | 40 | low:40 | FACTUAL-FP×10/NOISE×30 | No STOPSIGNAL directive |
| AZURE-007 | 39 | high:39 | TP | Key Vault without firewall |
| AZURE-038 | 39 | medium:39 | TP | Key Vault not using RBAC authorization |
| AZURE-187 | 39 | high:39 | TP | Key Vault network ACLs allow public traffic |
| K8S-015 | 33 | low:33 | TP | Container without readiness probe |
| K8S-028 | 33 | medium:33 | TP | Container without read-only root filesystem |
| K8S-029 | 33 | medium:33 | TP | Container without seccomp profile |
| K8S-030 | 33 | medium:33 | TP | Container does not drop ALL capabilities |
| DOCKER-022 | 29 | low:29 | TP | COPY of entire build context |
| AWS-311 | 28 | medium:28 | TP | RDS without IAM database authentication |
| AWS-540 | 28 | high:28 | TP | RDS MySQL/Postgres instance without IAM database authentication |
| AWS-543 | 28 | low:28 | TP | RDS instance without CloudWatch log exports |
| AWS-546 | 28 | low:28 | TP | RDS instance without copy_tags_to_snapshot |
| AWS-605 | 28 | low:28 | TP | RDS instance without enhanced monitoring |
| AWS-608 | 28 | low:28 | TP | RDS instance without Performance Insights |
| AWS-710 | 28 | medium:28 | TP | RDS master password not managed by Secrets Manager |
| AWS-607 | 26 | low:26 | TP | RDS Postgres instance without query logging |
| AWS-310 | 22 | medium:22 | TP | EC2 instance without detailed monitoring |
| AWS-683 | 22 | low:22 | TP | EC2 instance without termination protection |
| AWS-339 | 22 | high:22 | TP | Hardcoded credentials in resource config |
| DOCKER-005 | 22 | low:22 | TP | No HEALTHCHECK directive |
| AWS-443 | 21 | high:21 | TP | S3 bucket policy does not enforce TLS (SecureTransport) |
| AWS-445 | 21 | medium:21 | TP | S3 bucket without server access logging |
| AWS-601 | 21 | low:21 | TP | S3 bucket without lifecycle configuration |
| K8S-006 | 19 | medium:19 | TP | Container without resource limits |
| AZURE-043 | 18 | low:18 | TP | Key Vault not using premium SKU |
| AZURE-119 | 17 | high:17 | TP | Storage account allows public nested item access |
| AZURE-122 | 17 | high:17 | TP | Storage blobs allow public access |
| AZURE-195 | 17 | medium:17 | TP | Storage account allows nested public items |
| K8S-014 | 16 | low:16 | TP | Container without liveness probe |
| AWS-672 | 14 | low:14 | NOISE | IAM user has no tags |
| AWS-852 | 11 | low:11 | TP | S3 bucket encrypted with AWS-managed key, no customer-managed key |
| AWS-008 | 11 | medium:11 | TP | RDS instance without deletion protection |
| AWS-446 | 11 | medium:11 | TP | RDS instance without Multi-AZ |
| DOCKER-015 | 11 | low:11 | NOISE | No WORKDIR directive |
| AZURE-244 | 10 | high:10 | TP | NSG inline security rule open to the internet |
| AWS-012 | 10 | medium:10 | TP | S3 bucket without versioning |
| K8S-020 | 10 | medium:10 | TP | Service exposed externally |
| AWS-004 | 8 | high:8 | TP | Security group ingress open to the world |
| AWS-501 | 6 | critical:6 | TP | IAM policy allows privilege escalation (create policy + attach policy) |
| AWS-502 | 6 | critical:6 | TP | IAM policy allows privilege escalation via iam:PassRole on * with compute launch |
| AWS-503 | 6 | high:6 | TP | IAM policy allows data exfiltration primitives |
| AWS-504 | 6 | high:6 | TP | IAM permissions management actions allowed on all resources |
| AWS-206 | 5 | high:5 | TP | S3 bucket without public access block |
| AWS-104 | 5 | critical:5 | TP | Public S3 exfiltration path |
| AWS-857 | 5 | high:5 | TP | Secret in plaintext CloudFormation parameter default |
| AZURE-106 | 5 | high:5 | TP | MSSQL server allows public network access |
| AZURE-081 | 4 | high:4 | TP | CosmosDB account without IP range filter |
| AZURE-263 | 4 | high:4 | TP | Cosmos DB account with public network access enabled |
| AZR-001 | 4 | high:4 | TP | Storage account allows public blob access |
| AWS-333 | 3 | high:3 | TP | Inline admin policy attached to role/user/group |
| AWS-102 | 3 | high:3 | TP | IAM managed policy grants administrative access |
| AZURE-015 | 3 | high:3 | TP | AKS cluster without network policy |
| AZURE-127 | 3 | high:3 | TP | AKS cluster with local admin accounts enabled |
| AZURE-229 | 3 | high:3 | TP | AKS API server exposed without authorized IP ranges |
| AWS-001 | 3 | high:3 | TP | S3 bucket without server-side encryption |
| COMPOSE-005 | 3 | high:3 | TP | Sensitive host path mounted |
| AWS-305 | 2 | high:2 | TP | EKS cluster with public endpoint |
| GCP-010 | 2 | high:2 | TP | GKE cluster without network policy |
| GCP-047 | 2 | high:2 | TP | GKE cluster without workload identity |
| GCP-113 | 2 | high:2 | TP | GKE control plane publicly reachable |
| GCP-008 | 2 | high:2 | TP | Cloud SQL instance without SSL enforcement |
| GCP-016 | 2 | high:2 | TP | GCS bucket without versioning |
| GCP-025 | 2 | high:2 | TP | GCS bucket without customer-managed encryption |
| AWS-320 | 1 | high:1 | TP | ElastiCache replication group without transit encryption |
| AWS-321 | 1 | high:1 | TP | ElastiCache replication group without at-rest encryption |
| GCP-005 | 1 | high:1 | TP | GCS bucket without uniform bucket-level access |
| AWS-538 | 1 | high:1 | TP | Secret in plaintext variable default |
| GCP-061 | 1 | high:1 | TP | Compute instance boot disk without customer-managed encryption |
| AWS-319 | 1 | high:1 | TP | OpenSearch domain without encryption at rest |
| AWS-507 | 1 | high:1 | TP | Search domain outside VPC |
| AWS-637 | 1 | high:1 | TP | Elasticsearch/OpenSearch domain without HTTPS enforcement |
| AWS-811 | 1 | high:1 | TP | OpenSearch domain without advanced security options |
| AWS-201 | 1 | high:1 | TP | Load balancer internet-facing |
| AWS-203 | 1 | high:1 | TP | Load balancer not dropping invalid headers |
| AWS-329 | 1 | high:1 | TP | Load balancer target group uses plain HTTP |
| AWS-506 | 1 | high:1 | TP | Public load balancer without WAF |
| AWS-858 | 1 | high:1 | TP | Security group exposes database port 5432 to the internet (all ports open) |
| K8S-008 | 1 | high:1 | TP | Pod with hostPID enabled |
| K8S-011 | 1 | high:1 | TP | Pod with hostPath volume |
| K8S-027 | 1 | high:1 | TP | Workload defines no security context |


## Verification battery

- **Build/vet/gofmt**: `go build ./...` clean, `go vet ./...` clean,
  `gofmt -l cmd internal` empty (one realignment commit for the two
  Azure pack files whose registration lists changed).
- **Tests**: `go test ./...` — 32/32 packages pass. Every changed
  rule has twin tests (positive fires / negative silent) in pack
  style; parity `expect.json` files were re-recorded with
  `benchmark/parity/record.py` (only files whose findings changed)
  and the `rds_mixed` regression golden regenerated
  (`AEGIS_UPDATE_GOLDEN=1`) — its diff is exactly the two AWS-540
  findings removed + the AWS-311 description update.
- **Rescore** (binary rebuilt to `/tmp/aegis-item1/aegis`, sweep
  outputs regenerated — note `sweep_scanner.py` is resume-based and
  skips existing outputs, so `scanner-output/aegis/r4*.json` was
  cleared first): raw findings 2,417 → 2,234 (before-total re-measured
  with a Sprint-1-close build for an identical methodology); **TP 136
  (unchanged), FN 0 (unchanged)**, FP candidates 2,227 → 2,044. The
  findings drop (−183) equals the candidate drop exactly. Every
  deprecated rule went to zero candidates; no surviving rule gained
  candidates.
- **Collateral** (six `~/workspace/aegis-multiscan/` targets; SUMMARY
  baselines were recorded pre-Sprint-1 with binary `f1c4f7d`, so
  Sprint-2 deltas are measured against a Sprint-1-close build,
  `d0eda66`):

| Target | SUMMARY | Sprint-1 close | Sprint 2 | Sprint-2 delta explained |
|---|---|---|---|---|
| TerraGoat | 527 | 525 | 513 | −12: 540, 547, 007, 075, 119×2, 191×2, 230, 245, GCP-010, GCP-048 — all §A duplicates |
| vuln-500 | 4,562 | 4,586 | 4,426 | −160: 540×48, 007×16, 027×32, 119×32, 191×32 |
| Parity fixtures | 1,245 | 1,209 | 1,159 | −50: 540×20, 119×12, 191×16, DOCKER-017 −1, DOCKER-018 −1 (build stages) |
| k8s-vuln | 17 | 17 | 17 | — |
| docker-vuln | 17 | 17 | 17 | — (single-stage Dockerfile: final-stage gate inert) |
| pulumi-vuln | 6 | 6 | 6 | — |

  No unexplained drop on any target; every canonical survivor still
  fires wherever its deprecated duplicates did (e.g. AZURE-121's count
  is unchanged on vuln-500 where 027's 32 firings vanished).

## Commits (local only, never pushed)

- `c826f7b` FP kill AZURE-191/007/119/027 (also swept in the previously
  untracked Sprint plan doc `24_FP_FN_ELIMINATION_PLAN.md` via
  `git add -A` — noted for transparency)
- `0907bc1` FP kill AZURE-075/230/245
- `76ed4ed` FP kill AWS-540 + AWS-311 engine scoping
- `336dff8` FP kill AWS-547/840
- `c6a246e` FP kill AWS-418/811/812
- `e4939c8` FP kill GCP-048/010
- `5e79bf4` FP kill DOCKER-017/018 final-stage gating
- `74f0a55` gofmt realignment
- `c342aeb` parity/golden expectation updates
- Final commit: this report, `labels/fp-adjudicated-sprint2.json`,
  and the regenerated sweep outputs.

Registry: 1,155 → 1,140 rules. Deprecated map: 52 → 67 entries.

## Not fixable / deliberately untouched

- NOISE families at Low (§above): no lower severity exists; removal
  would break the hygiene pack's design contract.
- GCP-010's surviving canonical (111) is Medium where 010 was High —
  accepted severity normalization, consistent with repo precedent;
  flagged here rather than hidden.
- The stale `finding_total`/hash fields in a few pre-existing parity
  `expect.json` files (e.g. storage-public-gcp recorded 9 with a
  findings sum of 8) were corrected by re-recording; they predate
  this sprint and the parity test does not consume the hash.
