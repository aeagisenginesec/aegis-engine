# Round-6 Final Evaluation Report — Aegis v2.3.0 vs Checkov 3.3.26

**Date:** 2026-11-25
**Aegis:** frozen `~/workspace/aegis-engine-v230/aegis` — version `2.3.0`
(build `2026-11-24T20:40:50Z`, commit
`0dc955c7ec49b0b0023a5eda8af26b8fd033b7d6`) — **1,140 rules**
**Binary SHA-256:** `4ad966af8c79a3293c0ff7563fc23d3f1e741aebc5c696950c1cc3ea592bb277`
**Checkov:** `3.3.26` (Python 3.12.3), binary SHA-256
`9cda52aeac4fefdfe3e72114d2e8b8a2da0902788bb61fef03ab52c473bbf1f2`
**Protocol:** `docs/audit/27_EVAL_R6_PROTOCOL.md` (frozen 2026-11-25, Addendum 1)
**Verdict:** **NOT YET** — Aegis passes (c) fastest by a 473× margin, but
fails (a) highest F1 (pairwise CI contains 0: [−0.024, +0.238]) and fails
(b) lowest FP rate (Checkov leads on the point estimate, 0.000 vs 0.026,
and the CI is inconclusive, not a tie). Under the pre-registered
all-three win condition, no superiority claim is earned.

## Win condition

Aegis wins iff ALL THREE hold vs Checkov 3.3.26:
- (a) **Highest F1** — PASS iff the pairwise (Aegis − Checkov) F1 95% CI
  is entirely above 0;
- (b) **Lowest FP rate** (factual standard) — PASS iff the
  (Checkov − Aegis) FP-rate 95% CI is entirely above 0; a CI containing 0
  is a FAIL — a genuine tie iff half-width < 2pp, otherwise inconclusive;
- (c) **Fastest median scan time** — PASS iff Aegis median-of-medians is
  > 2× faster than Checkov.

No partial credit. No threshold changes after seeing results.

## 1. Why R6 exists

R5 was the Aegis-vs-Checkov mission's Phase A blind eval with an FN
ground truth, but its headline numbers were published under an
adjudication standard that scored "real but immaterial / by-design /
not-in-ground-truth" findings as FP — the carried closeout precision of
0.090 was an artifact of that standard, corrected after the fact to
0.79–0.92 under the factual standard
(`raw/final-eval-r5/PRECISION-RECONCILIATION.md`). R6 is the clean round:
a fresh 210-project blind corpus, a pre-registered frozen protocol, and
the factual FP standard (FP = factually wrong only; real-but-immaterial
findings are LABEL-NOISE, tracked separately, never counted as FP)
declared BEFORE any scanning. R6 decides, on the factual standard, whether
Aegis v2.3.0 beats Checkov 3.3.26 on all three pre-registered criteria.

**Bottom line up front:** on fresh blind code Aegis finds more true
positives than Checkov (76 vs 47 GT concepts; recall 0.513 vs 0.393) and
scans 473× faster, but the F1 lead (+0.108 point estimate) is not
statistically decisive (95% CI [−0.024, +0.238] contains 0), and Checkov
has the lower FP rate on the point estimate (0.000 vs 0.026, 0 vs 2 FPs)
with an inconclusive CI. On the formats Checkov supports, the two
scanners are effectively tied on F1 (0.660 vs 0.667); Aegis's overall F1
lead comes entirely from Pulumi + Compose, which Checkov does not scan.
The remaining work is recall on both sides — 57 Aegis FNs and 71 Checkov
FNs — and, for Aegis, the Azure/CFN gap (Checkov leads those formats by
large margins).

## 2. Corpus

**210 NEW projects** (ids `r6001`–`r6210`), seed 20261125, 226 files.

| Format | Count | Profile | Count | Difficulty | Count |
|---|---|---|---|---|---|
| terraform | 40 | vulnerable | 84 | easy | 92 |
| cloudformation | 30 | mixed | 61 | medium | 80 |
| arm | 15 | secure | 65 | hard | 38 |
| bicep | 15 | | | | |
| pulumi | 20 (10 `template:`-nested + 10 top-level) | | | | |
| dockerfile | 30 | | | | |
| compose | 25 | | | | |
| kubernetes | 35 | | | | |

- **Freshness verified by hash:** zero SHA-256 overlap vs the R2/R3/R4/R5
  corpora, 0 within-R6 duplicates.
- **Discrepancy vs protocol §2 (flagged, protocol wins):** the protocol's
  §2 table says cloud `aws 60 / gcp 1`; the corpus MANIFEST.json and
  STATS.json say **aws 59 / gcp 2**. Formats, profiles, and difficulty
  match the protocol exactly. The per-provider table in §6.2 uses the
  corpus's own counts (aws 59, azure 35, gcp 2, multi 24, none 90).
- **Known corpus defects (from `labels/HANDOFF.md`, documented, not
  hidden):**
  - ARM merge bug, fixed under protocol Addendum 1 (projects r6079,
    r6080, r6084).
  - K8s twin-name collisions (r6184, r6202, r6205, r6207, r6209): two
    Deployments named `shop-<sfx>` in one file, so findings are
    twin-ambiguous — one twin is vulnerable, the other hardened.
  - Secure-profile projects can contain firm concepts (e.g. literal
    passwords in "secure" RDS billing blocks).
  - 5 new blocks were never picked by the generator.
  - Judgment call most likely to be disputed: r6037 `secret-hardcoded`
    for a Secrets Manager `secret_version` literal.

## 3. Ground truth

- **Two sequential labeling passes (A, then B)** over the generated code,
  both reading code only — never scanner output, never the injection
  plan, never the other pass's file.
- **Labeler-independence limitation (disclosed upfront, protocol §3):**
  the same agent authored the generator and both labeling passes;
  independence is procedural only (Pass B performed without opening Pass
  A's file, using a different implementation) — the same limitation R3–R5
  disclosed. This is NOT personal independence.
- **Agreement (pre-adjudication):** raw agreement **0.9964**, Jaccard
  **0.9929** (Pass A 140, Pass B 141; the single B-only concept is r6007
  `opensearch-tls-old`).
- **Ground truth: 141 firm concepts across 111 projects.** Per-class
  counts (GT): `secret-hardcoded` 36, `sg-open-ssh` 4, `k8s-run-as-root`
  5, `apigw-no-auth` 7, `db-public` 6, `sqs-public-policy` 5,
  `az-storage-http-only` 5, `docker-multistage-secret` 4,
  `compose-host-pid` 3, `compose-cap-add-sys-ptrace` 3, `az-sql-weak-tls`
  3, `compose-db-port-published` 3, `sg-admin-public` 3,
  `lambda-invoke-public` 3, `compose-cap-add` 2, `ecr-public-policy` 2,
  `gcp-function-public` 2, `k8s-cap-sys-admin` 2, `kafka-plaintext` 2,
  `redis-non-ssl` 3, `k8s-writable-rootfs` 3, `ecs-public-ip` 4,
  `k8s-host-namespace` 2, `nsg-rdp-public` 2, `storage-unencrypted` 2,
  `efs-unencrypted` 1, `elasticache-no-auth` 1,
  `neptune-no-encryption` 1, `opensearch-no-https` 1,
  `opensearch-tls-old` 1, `k8s-allow-priv-esc` 1, `k8s-privileged` 1,
  `k8s-seccomp-unconfined` 1, `k8s-cluster-admin-binding` 2,
  `k8s-hostpath-writable` 2, `k8s-ingress-no-tls` 1,
  `docker-curl-pipe-shell` 1, `alb-tls-old` 2,
  `cloudfront-origin-http-only` 1, `compose-host-network` 1,
  `compose-privileged` 1, `az-mysql-public` 1, `az-vm-password-auth` 1,
  `ebs-snapshot-public` 1, `sns-public-policy` 2, `bigquery-public` 1.
- **FN manifest (sealed, `sealed/fn-manifest.json`):** 178 entries / 177
  unique (project, class) pairs; 117 firm + 60 soft. **24 GT firm
  concepts are not in the manifest.** Per protocol §6, TP is counted
  against GT (141) and recall/FN against the FN manifest (firm
  denominator 117). The two denominators are different by design and
  must not be conflated: e.g. Aegis's 14 GT `secret-hardcoded` TPs are
  outside the manifest-firm set, so they raise precision but not the
  manifest recall (see §5.6).
- **Classifier:** `score_r6.py` taxonomy (R4 table + R5 additions +
  24 new R6 classes, plus one literal keyword added to `sg-open-ssh`).
  One mechanical pre-final-scoring fix, documented in
  `labels/CLASSIFIER_CHANGELOG.md`: a `big query` keyword variant for
  `bigquery-public` (the classifier's camelCase splitting defeated its
  own keyword). Deliberately NO semantic title→class mappings added after
  seeing results (R4 §5.6 precedent): near-misses are reported as
  matcher limitations, not rescored. The one exception to "no post-result
  fixes" is none — the `bigquery-public` fix was made during scorer
  validation, before final scoring.
- **Scorer verification:** GT sanity 141/141 canonical class present
  (37 multi-mapped, documented in the scorer); FN reconciliation asserts
  pass exactly — 178 entries, 177 unique, 117 firm, 60 soft, 24 GT extras.

## 4. Scanners

| Scanner | Version | Config | Accuracy | Timing |
|---|---|---|---|---|
| Aegis | 2.3.0, frozen binary (1,140 rules) | `scan <dir> --format=json` | 210/210 | 30×5 |
| Checkov | 3.3.26 (Python 3.12.3) | `-d <dir> -o json --quiet` | 210/210 | 30×5 |

**Native coverage gaps (disclosed, protocol §6):**
- Checkov: no misconfiguration checks for Pulumi or compose (secrets
  framework only); scans TF/CFN/ARM/Bicep/Dockerfile/K8s.
- Aegis: scans all 8 formats.

**Timing methodology:** 30-project systematic subset (protocol §5's
wording — "5 per format group + Pulumi both layouts" — is ambiguous
across 8 formats; the interpretation used is recorded in
`timing-subset.json` and `RUNLOG.md`: 6 groups × 5 = terraform 5,
cloudformation 5, arm+bicep 5 [3 ARM + 2 Bicep], pulumi 5 [3
template-nested + 2 top-level], dockerfile+compose 5 [3 Dockerfile +
2 Compose], kubernetes 5; systematic evenly-spaced picks within each
stratum). 5 timed runs per scanner per project. Median of per-project
medians.

**Infrastructure note:** a sandbox runtime restart at ~14:55 UTC on
2026-11-25 killed the Checkov sweep after accuracy completed (210/210
files intact, verified JSON-parseable) and wiped the live log in /tmp.
The per-project exit codes from that accuracy run were lost with the log
and are DERIVED in `RUNLOG.md` from output content (Checkov exits 1 iff
≥ 1 failed check: 132 exit 1, 78 exit 0; no empty/unparseable outputs).
The timing phase was re-run cleanly (14:56–15:10 UTC, 30×5, wall
796.8 s). The first timing relaunch passed `--timing-only` (with dashes)
which the runner's MODE check does not recognize, so it exited in 0 s
writing empty logs; that run's log is preserved as
`checkov-timing-sweep-BROKEN-MODE.log` and the rerun used the bare mode
argument. No data was affected. The timing-only rerun overwrote
`scanner-output/checkov/RUNLOG.md` and `FAILURES.json` with timing-only
content; the accuracy-phase record lives in the top-level `RUNLOG.md`.

## 5. Results

### 5.1 Primary metrics (firm concepts, adjudicated; 95% CIs via cluster bootstrap by project, B=10,000, seed 20261125)

| Scanner | F1 [95% CI] | Precision [95% CI] | Recall [95% CI] | FP rate [95% CI] | FN rate | TP | FP | FN | Findings |
|---|---|---|---|---|---|---|---|---|---|
| **Aegis** | **0.672 [0.583, 0.747]** | 0.974 [0.934, 1.000] | 0.513 [0.417, 0.605] | 0.026 [0.000, 0.066] | 0.487 | 76 | 2 | 57 | 1,445 |
| **Checkov** | 0.564 [0.467, 0.654] | **1.000 [1.000, 1.000]** | 0.393 [0.305, 0.486] | **0.000 [0.000, 0.000]** | 0.607 | 47 | 0 | 71 | 1,175 |

Factual precision (secondary, (TP+LN)/(TP+FP+LN) over adjudicated
non-hygiene findings): Aegis **0.998 [0.996, 1.000]**, Checkov **1.000
[1.000, 1.000]**. Findings counts are post-hygiene-exclusion (Aegis
1,445 after excluding 31 findings on the 9 protocol §4 hygiene rule
IDs; Checkov 1,175, hygiene-excluded 0 — the §4 hygiene set is Aegis
rule IDs only). TP is counted against GT (141); FN/recall against the
FN manifest (firm 117).

### 5.2 Pairwise differences (95% CI)

| Comparison | Difference [95% CI] | Mean | Entirely >0? |
|---|---|---|---|
| F1 Aegis − Checkov | [−0.0235, +0.2380] | +0.1068 | **No — contains 0** |
| FP rate Checkov − Aegis | [−0.0656, +0.0000] | −0.0258 | **No — contains 0** |

The F1 point estimate favors Aegis (+0.108) but the CI's lower bound is
−0.024: the lead is not statistically decisive at this corpus size.
The FP-rate point estimate favors **Checkov** (−0.026: 0.000 vs 0.026);
the CI contains 0 only because Aegis's FP count is 2, so its FP-rate CI
spans 0–6.6%.

### 5.3 Timing (median of per-project medians)

| Scanner | Median | Per-project median range | Ratio vs Aegis |
|---|---|---|---|
| **Aegis** | **0.0101 s** | 0.0072–0.0124 s | 1× |
| Checkov | 4.7603 s | 4.2928–7.2356 s | 473.3× slower |

### 5.4 FP adjudication summary

| Scanner | Unmatched | Adjudicated | TP (genuine, labeler-missed) | of which classifier-miss | HYGIENE | LABEL-NOISE | FP |
|---|---|---|---|---|---|---|---|
| Aegis | 1,368 | full (1,368) | 109 | 23 | 167 | 1,090 | **2** |
| Checkov | 1,127 | full (1,127) | 74 | 31 | 18 | 1,035 | **0** |

Full adjudication of every unmatched finding for both scanners, under
the protocol's FACTUAL FP standard — FP means factually wrong only;
real-but-immaterial/by-design findings are LABEL-NOISE, never FP.
Per-finding verdicts with justifications:
`labels/fp-adjudicated-aegis.json`,
`labels/fp-adjudicated-checkov.json`.

- **Aegis FP = 2.** (1) AEGIS-K8S-029 on r6176 — "Container without
  seccomp profile" is factually wrong: the DaemonSet pod spec sets
  `seccompProfile: {type: Unconfined}` (inherited by containers); Aegis
  checks container-level only. The Unconfined profile is itself the GT
  firm concept, matched by AEGIS-K8S-017. (2) AEGIS-DOCKER-005 on r6139
  — the Dockerfile HAS `HEALTHCHECK NONE` (line 7); the rule misreads an
  explicit disable as an absence. Verification: every K8s absence rule
  checked per workload (segmentation verified); AWS/Azure/GCP absence
  rules batch-falsified (567 checked in batch 1, 20 candidates; 310 in
  batch 2, 10 candidates) — every candidate individually confirmed as a
  regex over-match (wrong resource, wrong value, or sibling workload's
  setting), 0 additional FPs. Docker rules verified per stage.
  Context-sensitive rules (AWS-004, AWS-001, AWS-857, AWS-534, AWS-324,
  AWS-637, AZURE-006/026/105/244, DOCKER-021, COMPOSE-002, K8S-026,
  K8S-020, GCP-113, AZURE-205/149) verified per finding against code.
- **Checkov FP = 0.** Every unmatched finding verified: K8s absence
  rules checked per workload with PyYAML (explicit-dangerous settings
  confirmed where present; unset ≠ explicit); 36 regex candidates over
  105 patterned rules batch-falsified, every candidate an over-match
  (e.g. the KMS SSE config belongs to a sibling bucket; the `Disabled`
  matches belong to sibling Key Vaults/storage accounts/SQL servers).
  Checkov does NOT repeat either Aegis FP: it emits no seccomp finding
  on r6176, and CKV_DOCKER_2 fires only on r6125/r6132/r6138, not r6139.
  Checkov source was read where the check's semantics were ambiguous
  (CKV_AZURE_59 inspects `publicNetworkAccess`, not blob public access,
  despite its name; CKV_AZURE_189 passes on Deny-by-default only with
  ipRules/subnet present; CKV_AZURE_178 requires an embedded admin SSH
  key).
- **Caveat (Aegis TPs, recorded, not rescored):** AWS-001/AWS-341
  findings are counted TP as missing-EXPLICIT-encryption findings. S3/SNS
  apply default encryption since 2023, so the residual risk is about
  explicit config/CMK, not plaintext storage. The same doctrine was
  applied to Checkov's equivalent checks (CKV_AWS_145, CKV_AWS_26/27).
- **Attribution artifact (Aegis, r6004):** the auto-matcher consumed
  AEGIS-GCP-006 for `bigquery-public` via the bare `bigquery` keyword;
  the finding that actually identifies the public-IAM condition,
  AEGIS-GCP-038, is adjudicated TP as a duplicate. The concept IS
  detected; the attribution is a classifier artifact.

### 5.5 Sensitivity: additive variant and classifier-miss-recovered recall

The primary metrics count TP/FN against the fixed firm universes
(protocol §6). Two sensitivity analyses, both R4/R5 precedent:

**Additive variant** — every adjudicated-TP unmatched finding
additionally counted as a true positive on the GT universe (upper bound;
includes near-duplicates of GT concepts):

| Scanner | Precision | Recall | F1 |
|---|---|---|---|
| Aegis | 0.989 | 0.740 | **0.847** |
| Checkov | 1.000 | 0.563 | 0.720 |

**Classifier-miss-recovered recall** — classifier-miss TPs that
identify a MISSED manifest-firm (project, class) pair count as
recovered recall (the classifier, not the scanner, missed them):

| Scanner | TP_fn | Recovered pairs | Recall (cm) |
|---|---|---|---|
| Aegis | 60 | 16 | **0.650** |
| Checkov | 46 | 22 | 0.581 |

Aegis still leads on both sensitivities, but the gap narrows on the
second: Checkov recovers more pairs (22 vs 16) because the keyword
classifier misses Checkov's phrasing more often. Reported primary recall
is classifier-mediated recall for both scanners.

### 5.6 False negatives — the FN profile

FN is scored against the FN manifest (firm 117). Aegis missed 57,
Checkov missed 71. Each missed pair was classified as a **near-miss**
(a related finding exists but the keyword classifier did not map it —
reported, NOT rescored) or a **true gap** (no related finding on the
project).

**Aegis — 57 missed (16 near-miss, 41 true gap):**

| Class | Missed | Projects |
|---|---|---|
| `secret-hardcoded` | 14 (4 near-miss, 10 gap) | r6014, r6088, r6105, r6108, r6114, r6117, r6120, r6122, r6124, r6126, r6130, r6133, r6141, r6188 |
| `az-storage-http-only` | 5 (near-miss) | r6074, r6079, r6080, r6084, r6095 |
| `sqs-public-policy` | 5 (gap) | r6047, r6061, r6067, r6068, r6110 |
| `apigw-no-auth` | 4 (gap) | r6041, r6047, r6057, r6107 |
| `db-public` | 4 (gap) | r6054, r6059, r6060, r6067 |
| `docker-multistage-secret` | 4 (1 near-miss, 3 gap) | r6121, r6124, r6129, r6143 |
| `az-sql-weak-tls` | 3 (near-miss) | r6086, r6095, r6099 |
| `compose-db-port-published` | 3 (gap) | r6151, r6152, r6164 |
| `sg-admin-public` | 3 (near-miss) | r6017, r6043, r6056 |
| `ecr-public-policy` | 2 (gap) | r6056, r6113 |
| `gcp-function-public` | 2 (gap) | r6019, r6025 |
| `k8s-cap-sys-admin` | 2 (gap) | r6207, r6209 |
| `kafka-plaintext` | 2 (gap) | r6023, r6058 |
| `az-mysql-public` | 1 (gap) | r6072 |
| `az-vm-password-auth` | 1 (gap) | r6085 |
| `ebs-snapshot-public` | 1 (gap) | r6035 |
| `sns-public-policy` | 1 (gap) | r6066 |

Aegis near-misses (finding exists, doesn't map): AEGIS-AZURE-026
"Storage account allows HTTP traffic" (`az-storage-http-only` ×5);
AEGIS-AZURE-105 "MSSQL server not using TLS 1.2"
(`az-sql-weak-tls` ×3, maps to R4 `weak-tls` only); generic
AEGIS-AWS-004 (`sg-admin-public` ×3, R5 condition-relevance
principle); AEGIS-AWS-534 "Secrets in EC2 user_data" (r6014),
AEGIS-DOCKER-021 (r6124, r6133, r6143), AEGIS-K8S-026 (r6188) for
`secret-hardcoded` / `docker-multistage-secret`. True gaps confirmed by
inspecting project outputs (scanner emitted nothing on the project):
CFN `sqs-public-policy` (r6047), `compose-db-port-published` (r6151: db
publishes 5432:5432), Pulumi `secret-hardcoded` (r6105 config), CFN
`apigw-no-auth` (r6041), `docker-multistage-secret` (r6121),
`kafka-plaintext` (r6023: only MSK logging/monitoring findings),
`ecr-public-policy` (r6056), `db-public` via CFN parameter indirection
(r6054). Aegis's largest single FN class is `secret-hardcoded` (14 of
57) — but note the dual-denominator subtlety: Aegis DID detect 14 GT
`secret-hardcoded` concepts (all 14 GT TPs for that class), which sit
outside the manifest-firm set; the 14 missed here are the
manifest-firm ones. Both scanners miss the same 13
`secret-hardcoded` manifest pairs (r6014, r6105, r6108, r6114, r6117,
r6120, r6122, r6124, r6126, r6130, r6133, r6141, r6188) — a shared blind
spot, not a differentiator.

**Checkov — 71 missed (22 near-miss, 49 true gap):**

| Class | Missed | Projects |
|---|---|---|
| `secret-hardcoded` | 13 (1 near-miss, 12 gap) | r6014, r6105, r6108, r6114, r6117, r6120, r6122, r6124, r6126, r6130, r6133, r6141, r6188 |
| `k8s-run-as-root` | 5 (near-miss) | r6181, r6183, r6189, r6191, r6203 |
| `docker-multistage-secret` | 4 (gap) | r6121, r6124, r6129, r6143 |
| `sg-open-ssh` | 4 (near-miss) | r6028, r6051, r6052, r6068 |
| `az-sql-weak-tls` | 3 (near-miss) | r6086, r6095, r6099 |
| `compose-cap-add-sys-ptrace` | 3 (gap) | r6157, r6163, r6171 |
| `compose-db-port-published` | 3 (gap) | r6151, r6152, r6164 |
| `compose-host-pid` | 3 (gap) | r6162, r6167, r6168 |
| `ecs-public-ip` | 3 (gap) | r6103, r6104, r6116 |
| `k8s-writable-rootfs` | 3 (near-miss) | r6182, r6184, r6205 |
| `lambda-invoke-public` | 3 (near-miss) | r6008, r6028, r6038 |
| `alb-tls-old` | 2 (near-miss) | r6017, r6036 |
| `compose-cap-add` | 2 (gap) | r6173, r6174 |
| `ecr-public-policy` | 2 (gap) | r6056, r6113 |
| `k8s-cluster-admin-binding` | 2 (gap) | r6187, r6191 |
| `k8s-hostpath-writable` | 2 (gap) | r6179, r6200 |
| `kafka-plaintext` | 2 (1 near-miss, 1 gap) | r6023, r6058 |
| `redis-non-ssl` | 2 (gap) | r6115, r6117 |
| `sqs-public-policy` | 2 (gap) | r6068, r6110 |
| `apigw-no-auth` | 1 (gap) | r6107 |
| `cloudfront-origin-http-only` | 1 (gap) | r6018 |
| `compose-privileged` | 1 (gap) | r6166 |
| `docker-curl-pipe-shell` | 1 (gap) | r6134 |
| `ebs-snapshot-public` | 1 (gap) | r6035 |
| `k8s-ingress-no-tls` | 1 (gap) | r6192 |
| `sg-admin-public` | 1 (gap) | r6017 |
| `sns-public-policy` | 1 (gap) | r6066 |

Checkov near-misses: CKV_AWS_301 "Lambda function is not publicly
accessible" (×3, classifier maps the title to `db-public` /
`ecr-public-policy`); CKV_AWS_103 "load balancer is using at least TLS
1.2" (×2); CKV_AWS_24 "no security groups allow ingress from 0.0.0.0:0
to port 22" (×4, maps to `sg-open-world` only — title has no "ssh");
CKV_AZURE_52 "MSSQL is using the latest version of TLS encryption"
(×3, maps spuriously to `docker-latest`); CKV_K8S_23 / CKV_K8S_40
"Minimize the admission of root containers" / "Containers should run as
a high UID" (×5, explicit runAsUser 0 confirmed per workload);
CKV_K8S_22 "Use read-only filesystem for containers where possible"
(×3, explicit readOnlyRootFilesystem false confirmed);
CKV_AWS_81 "MSK Cluster encryption in rest and transit is enabled"
(r6058, CFN `ClientBroker: PLAINTEXT`); CKV_SECRET_6 "Base64 High
Entropy String" (r6014 — flags the secret-bearing user_data heredoc,
not a literal in the file). True gaps: all Pulumi projects with missed
concepts (12 projects) and all Compose projects with missed concepts
(12 projects) — Checkov emitted 0 findings on them; `k8s-hostpath-writable`
(r6179, r6200), `k8s-ingress-no-tls` (r6192: 40 findings, none on
Ingress TLS), `cloudfront-origin-http-only` (r6018: CKV_AWS_174 is
viewer-cert TLS, no origin-protocol check), `ebs-snapshot-public`
(r6035), `ecr-public-policy` (r6056), `sns-public-policy` (r6066: only
CKV_AWS_26 encryption), `sqs-public-policy` (r6068: only CKV_AWS_24),
`kafka-plaintext` (r6023: only CKV_AWS_80 MSK logging),
`sg-admin-public` (r6017: dynamic mgmt-ports block; CKV_AWS_25 fired
only on the static RDP SGs).
Misattribution, not a gap: on r6007 the auto-matcher consumed
CKV_AWS_248 (default security group) for `opensearch-no-https` and
CKV_AWS_317 (audit logging) for `opensearch-tls-old`, while the
findings that actually identify those conditions, CKV_AWS_83 (enforces
HTTPS) and CKV_AWS_228 (up-to-date TLS policy), are in the unmatched
set (adjudicated TP). Same pattern: r6012 Neptune (CKV_AWS_361 consumed,
CKV_AWS_44 is the real identifier), r6196 privileged (CKV_K8S_37
consumed, CKV_K8S_16 is the real identifier).

**Zero for both scanners:** `az-sql-weak-tls` is 0/3 by auto-match for
both (both have near-miss findings — AZURE-105 / CKV_AZURE_52);
`docker-multistage-secret` 0/4, `compose-db-port-published` 0/3,
`kafka-plaintext` 0/2, `ebs-snapshot-public` 0/1, `ecr-public-policy`
0/2 by auto-match for both (Aegis recovers 1 multistage pair via
DOCKER-021 in the cm sensitivity; Checkov recovers 1 kafka pair via
CKV_AWS_81).

## 6. Per-format and per-provider breakdowns

### 6.1 Per-format F1 (primary method; SKIP = scanner natively skips the format)

| Format | Aegis | Checkov |
|---|---|---|
| terraform | **0.864** | 0.718 |
| cloudformation | 0.385 | **0.800** |
| arm | 0.000* | **1.000** |
| bicep | 0.545 | **0.769** |
| pulumi | **0.556** | SKIP (0.000) |
| dockerfile | **0.154** | 0.000 |
| compose | **0.857** | SKIP (0.000) |
| kubernetes | **0.900** | 0.500 |

\* Aegis ARM precision is undefined (0 TP, 0 FP on ARM); the 0.000 is
the scorer's fallback for an empty positive set. Aegis's ARM recall is
genuinely 0.000 (0/6 manifest-firm concepts): all 6 are near-misses —
`az-storage-http-only` ×4 (AZURE-026 exists but doesn't map),
`az-mysql-public` ×1, `az-vm-password-auth` ×1 (true gaps). Checkov
sweeps ARM 6/6. Conversely, Checkov's Dockerfile precision is likewise
undefined (0 TP, 0 FP) with recall 0.000 (0/11).

Aegis leads on terraform, pulumi, dockerfile, compose, and kubernetes.
Checkov leads on cloudformation, arm, and bicep — and by large margins:
CFN F1 0.800 vs 0.385 (recall 0.667 vs 0.238), ARM 1.000 vs 0.000,
Bicep 0.769 vs 0.545. Aegis's weakest formats are Dockerfile (F1 0.154:
1 TP, 1 FP, recall 0.091 — the multistage-secret and curl-pipe-shell
classes are nearly undetected) and CloudFormation (F1 0.385). Checkov
matched zero concepts on Dockerfile despite nominal support (its checks
there cover only soft classes) and zero on Pulumi/Compose by design.

### 6.2 Per-provider F1

| Provider | Projects | Aegis | Checkov |
|---|---|---|---|
| aws | 59 | **0.656** (= Checkov) | **0.656** |
| azure | 35 | 0.348 | **0.733** |
| gcp | 2 | **1.000** (= Checkov) | **1.000** |
| multi | 24 | **0.737** (= Checkov) | **0.737** |
| none | 90 | **0.757** | 0.275 |

On AWS the two scanners are exactly tied (both tp_fn 20, fn 21, fp 0)
— the tie is in the underlying counts, not a rounding artifact. On
Azure Checkov leads decisively (recall 0.579 vs 0.211). The GCP tie is
a 2-concept sample, not evidence of parity. "None" (Compose + Dockerfile
+ K8s, 90 projects) is where Aegis's format coverage pays: F1 0.757 vs
0.275.

### 6.3 Coverage-adjusted view (metrics restricted to formats each scanner natively supports)

| Scanner | Supported projects | F1 | Precision | Recall | FP rate |
|---|---|---|---|---|---|
| Aegis (all 210) | 210/210 | 0.672 | 0.974 | 0.513 | 0.026 |
| Aegis (supported-165 only) | 165/210 | 0.660 | 0.968 | 0.500 | 0.032 |
| Checkov (supported-165 only) | 165/210 | **0.667** | 1.000 | 0.500 | 0.000 |

Restricting both scanners to the 165 formats Checkov supports, the F1
ordering FLIPS on the point estimate: Checkov 0.667 vs Aegis 0.660,
with IDENTICAL recall (46/92 = 0.500 each) — the difference is
precision (1.000 vs 0.968, i.e. Aegis's 2 FPs). Aegis's overall F1 lead
(0.672 vs 0.564) comes entirely from the 45 Pulumi + Compose projects
Checkov does not scan, where Aegis scores F1 0.556 (Pulumi) and 0.857
(Compose). This is the single most important qualification to the
headline table: on shared ground the scanners are tied; Aegis wins the
headline only through broader coverage.

### 6.4 Coverage matrix

| Format | Aegis | Checkov |
|---|---|---|
| terraform | ✓ | ✓ |
| cloudformation | ✓ | ✓ |
| arm | ✓ | ✓ |
| bicep | ✓ | ✓ |
| pulumi | ✓ | ✗ |
| dockerfile | ✓ | ✓ (0 matches) |
| compose | ✓ | ✗ |
| kubernetes | ✓ | ✓ |

✓ = scanner runs checks on the format; "(0 matches)" = ran but matched
zero firm concepts. ✗ = no misconfiguration checks for the format.

## 7. Per-criterion verdicts

- **(a) Highest F1: FAIL.** Aegis F1 0.672 [0.583, 0.747] vs Checkov
  0.564 [0.467, 0.654]. The pairwise difference CI is [−0.0235,
  +0.2380], mean +0.1068 — it contains 0, so the predeclared rule
  (CI entirely above 0) is not met. The point estimate favors Aegis by
  +0.108, but at this corpus size (117 manifest-firm concepts) the lead
  is not decisive. Note the lead is entirely coverage-driven (§6.3): on
  the 165 shared formats the point estimate flips to Checkov 0.667 vs
  Aegis 0.660.
- **(b) Lowest FP rate: FAIL — INCONCLUSIVE (CI contains 0, half-width
  ≥ 2pp).** Checkov FP rate 0.000, Aegis 0.026. The (Checkov − Aegis)
  difference CI is [−0.0656, +0.0000], half-width 0.0328 ≥ 0.02, so
  under the protocol's tie rule this is INCONCLUSIVE, not a genuine tie
  — and the point estimate favors Checkov, not Aegis. Aegis does not
  have the lowest FP rate on this corpus; Checkov does, by 2.6pp on the
  point estimate, though with only 2 Aegis FPs the difference is not
  statistically decisive.
- **(c) Fastest: PASS.** Aegis 0.0101 s vs Checkov 4.7603 s — 473.3×
  faster, far above the 2× threshold.

**Overall: NOT YET.** One of three criteria passes. This is a different
failure mode from R4 (where Aegis passed (a) and (c) and failed (b) on a
genuine KICS tie): in R6, (a) fails on a CI that contains 0 and (b)
fails with Checkov ahead on the point estimate.

## 8. Reconciliation: why rounds 2, 3, 4, 5, and 6 differ

| Round | Corpus | Scorer / GT scope | Aegis F1 | Aegis FP rate | Verdict |
|---|---|---|---|---|---|
| 2 | 205 projects, 416 firm concepts | min-counting, full FP adjudication (Aegis/Checkov), 400-samples (KICS/Trivy) | 0.367 [0.323, 0.411] | 0.733 | NOT YET |
| 3 | 210 projects, 150 firm critical/high concepts | same method, narrower GT (critical/high only) | 0.733 [0.674, 0.790] | 0.314 | NOT YET |
| Rescore | SAME 210 projects as R3, same labels/scorer | post-fix regression check | 1.000 | 0.000 | — (regression check) |
| 4 | 210 NEW projects, 136 firm concepts | same method as R3 + 8 new classes, classifier normalization fixes | 0.921 [0.880, 0.955] | 0.000 | NOT YET (KICS FP tie) |
| 5 | 210 NEW projects, 128 firm concepts (closeout) | carried adjudication standard (pre-reconciliation) | 0.141 [0.110, 0.173] | 0.919 | EARNED (under that standard) |
| 6 | 210 NEW projects, 141 GT / 117 manifest-firm concepts | factual FP standard, pre-registered | 0.672 [0.583, 0.747] | 0.026 | NOT YET |

Three distinct causes, not one:

1. **Different corpora.** Every round uses a fresh 210-project corpus
   with a different firm-concept universe (416 → 150 → 136 → 128 →
   141 GT / 117 manifest-firm). The F1 numbers are not comparable
   across rounds without this caveat — the denominator changed each
   time, and R6's recall denominator (117 manifest-firm) is narrower
   than its TP denominator (141 GT).
2. **Different scorers / adjudication standards.** R5's carried numbers
   (Aegis F1 0.141, point precision 0.090, FP rate 0.919) were computed
   under an adjudication standard that scored real-but-immaterial
   findings as FP. The R5 reconciliation re-verified the carried FP
   verdicts against source and corrected Aegis's precision to 0.79–0.92
   (TP/(TP+FP)) and factual precision to ~0.98 — **never quote R5's
   0.090 without that correction.** R6 uses the factual standard from
   the start, so R6's precision (0.974) and FP rate (0.026) are
   comparable to R5's CORRECTED figures (0.79–0.92), not to the carried
   0.090. R5's EARNED verdict was computed under the old standard; the
   correction only improves Aegis's standing, so the verdict stands,
   but its margins are not comparable to R6's.
3. **Tuning and corpus difficulty.** R4's 0.921 was measured on a
   corpus whose classes Aegis's accuracy-100 fixes covered well; R6's
   corpus is harder for Aegis in specific places (Azure ARM/Bicep
   near-misses, CFN public-policy classes, Dockerfile multistage
   secrets) and Checkov is genuinely strong on CFN/ARM/Azure. The gap
   between R4's 0.921 and R6's 0.672 is mostly corpus difficulty and
   the narrower manifest-firm recall denominator, not a regression in
   the engine: R6's factual precision (0.998) is the highest yet, and
   the engine's problem on this corpus is recall (0.513), the same
   diagnosis the R5 reconciliation reached ("recall 0.555 and coverage,
   not correctness of what fires").

The honest reading: Aegis v2.3.0 is a fast, factually precise scanner
(2 FPs in 1,445 findings) whose recall on fresh blind code is 0.513 —
better than Checkov's 0.393, but not decisively better on F1, and worse
than Checkov on Azure/CFN/ARM. The R4-era claim of near-parity with
perfection (0.921) did not survive contact with this corpus.

## 9. Limitations

- **Single-agent labeling.** Both labeling passes were performed by the
  same agent that authored the generator (procedural, not personal,
  independence) — same limitation as R3–R5, disclosed in protocol §3.
  Class-level agreement was high (Jaccard 0.9929), which bounds but
  does not eliminate labeler bias.
- **Matcher near-misses.** 16 of Aegis's 57 FNs and 22 of Checkov's 71
  FNs are findings that exist but don't map to GT classes (no semantic
  mappings added post-results, by design). Reported recall is
  classifier-mediated recall; the cm-recovered sensitivity (§5.5) puts
  Aegis at 0.650 and Checkov at 0.581.
- **Dual denominators.** TP is counted against GT (141); recall/FN
  against the FN manifest (firm 117). 24 GT firm concepts are not in
  the manifest. Any comparison that mixes the two denominators (e.g.
  reading recall off the TP table) is wrong.
- **Aegis ARM precision undefined.** 0 TP and 0 FP on ARM; the 0.000 in
  the per-format table is the scorer's fallback, not a measured rate.
  Same for Checkov on Dockerfile/Pulumi/Compose.
- **Timing-subset interpretation.** Protocol §5's "5 per format group +
  Pulumi both layouts" for 30 projects is ambiguous across 8 formats;
  the 6-group interpretation used is recorded in `timing-subset.json`
  and §4. A different stratification would move the medians slightly;
  the 473× ratio makes criterion (c) insensitive to it.
- **Protocol discrepancies (flagged, not silently fixed):** cloud
  counts aws 60/gcp 1 in §2 vs aws 59/gcp 2 in the corpus manifests;
  §11 names the report `27_FINAL_EVAL_R6_REPORT.md` but 27 is the
  protocol itself, so this report is `28_FINAL_EVAL_R6_REPORT.md`.
- **Checkov accuracy exit codes derived, not observed.** The original
  per-project exit codes were lost in the 14:55 UTC sandbox restart;
  the 132 exit-1 / 78 exit-0 split is derived from failed-check
  presence in the outputs (see §4). No output was empty or
  unparseable, so no error exits are hidden in that derivation.
- **K8s twin ambiguity.** On r6184, r6202, r6205, r6207, r6209 two
  Deployments share a name in one file; per-workload verification
  confirms one twin is vulnerable and the other hardened, but the
  finding's resource identity cannot distinguish them. The GT concept
  per project is still counted once.
- **Synthetic corpus.** All 210 projects are generator-built, not real
  repositories. Real-world code has messier shapes (modules, dynamic
  blocks, cross-file references) that this benchmark does not exercise.
- **AWS-001/AWS-341 TP caveat.** Counted as TP for missing EXPLICIT
  encryption; S3/SNS default encryption since 2023 means the residual
  risk is about explicit config/CMK, not plaintext storage (§5.4).

## 10. Reproducible commands

```bash
cd docs/audit/raw/final-eval-r6
python3 sweep_r6.py aegis            # accuracy + timing (Aegis)
python3 sweep_r6.py checkov          # accuracy + timing (Checkov)
python3 score_r6.py                  # auto-scores both scanners
python3 adjudicate_aegis.py          # full Aegis FP adjudication
python3 adjudicate_checkov.py        # full Checkov FP adjudication
python3 stats_r6.py                  # cluster bootstrap (B=10,000, seed 20261125) + decision
```

Raw outputs: `scanner-output/{aegis,checkov}/`
Labels: `labels/` (ground truth, adjudication logs, FP adjudications,
classifier changelog)
Scores: `scores/scores.json`, `scores/stats.json`, `scores/breakdowns.json`
Run log: `RUNLOG.md` (top-level; Checkov accuracy-phase record lives
there, since the scanner-output RUNLOG was overwritten by the timing-only
rerun)

## Verdict: NOT YET

Aegis passes (c) fastest (0.0101 s, 473× faster than Checkov) by a
decisive margin, and holds factual precision 0.998 with only 2 false
positives in 1,445 findings. It fails (a) highest F1 — 0.672 vs 0.564,
pairwise CI [−0.024, +0.238] contains 0 — and fails (b) lowest FP rate
— Checkov 0.000 vs Aegis 0.026, CI inconclusive with Checkov ahead on
the point estimate. Under the pre-registered all-three win condition, no
superiority claim is earned.

What R6 does support, without overclaiming: on this fresh 210-project
corpus, Aegis has the highest point-estimate F1, the fastest scans by
473×, the broadest format coverage, the best per-format F1 in 5 of 8
formats, and 2 false positives across 1,445 findings — while finding
1.6× more true positives than Checkov (76 vs 47). What it does NOT
support: a decisive F1 lead (the CI contains 0), the lowest FP rate
(Checkov's 0.000 is lower), or parity on shared formats (on the 165
formats Checkov supports, F1 is 0.660 vs 0.667 — a tie, with Checkov
ahead on the point estimate). The remaining work is recall: 57 Aegis
FNs, led by `secret-hardcoded` (14), `az-storage-http-only` (5, all
near-miss), `sqs-public-policy` (5), `apigw-no-auth` (4), `db-public`
(4), and `docker-multistage-secret` (4) — plus the Azure/CFN gap, where
Checkov leads by 0.39 and 0.42 F1 respectively.
