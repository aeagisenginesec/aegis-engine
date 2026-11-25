# Round-7 Final Evaluation Report — Aegis v2.3.0 (Phase B build) vs Checkov 3.3.26

**Date:** 2026-11-25
**Aegis:** Phase B merged build, branch `phase-b/measure-combined`, commit
`ca5e7f0` — version `2.3.0` — **1,148 rules**, binary `/tmp/aegis-phaseb-r7`
**Binary SHA-256:** `144a64dfd3cae0edae4ba4924492b49b3642e633121813590286d7706a5bd2c2`
**Checkov:** `3.3.26` (Python 3.12.3), binary SHA-256
`9cda52aeac4fefdfe3e72114d2e8b8a2da0902788bb61fef03ab52c473bbf1f2`
**Protocol:** `docs/audit/31_EVAL_R7_PROTOCOL.md` (frozen 2026-11-25, Addendum 1)
**Verdict:** **NOT YET** — Aegis passes (a) highest F1 decisively
(pairwise CI [+0.302, +0.500]) and (c) fastest by a 571.5× margin, but
fails (b) lowest FP rate on a genuine 0–0 tie: both scanners have
**zero** false positives, so the (Checkov − Aegis) FP-rate CI is exactly
[0.000, 0.000]. Under the pre-registered all-three win condition, no
superiority claim is earned — this time the blocker is not a weakness in
either scanner but the criterion itself (see §7).

## Win condition

Aegis wins iff ALL THREE hold vs Checkov 3.3.26:
- (a) **Highest F1** — PASS iff the pairwise (Aegis − Checkov) F1 95% CI
  is entirely above 0;
- (b) **Lowest FP rate** (factual standard) — PASS iff the
  (Checkov − Aegis) FP-rate 95% CI is entirely above 0; a CI containing 0
  is a FAIL — a genuine tie iff half-width < 2pp, otherwise inconclusive;
  a genuine 0–0 tie is a FAIL;
- (c) **Fastest median scan time** — PASS iff Aegis median-of-medians is
  > 2× faster than Checkov.

No partial credit. No threshold changes after seeing results.

## 1. Why R7 exists

R6 was the clean blind round under the factual FP standard: Aegis 76 vs
Checkov 47 true positives, recall 0.513 vs 0.393, speed 473× — but the
F1 lead (+0.108) was not decisive (95% CI [−0.024, +0.238]) and Checkov
had the lower FP rate (0.000 vs 0.026). Verdict: NOT YET, 1 of 3.

Phase B then closed the R6 gaps on the **frozen R6 corpus**: 8 new rules,
the Pulumi adapter fixed (7 zero-finding projects → recall 1.000),
CloudFormation flipped from 0.385 to 0.923. On that tuned corpus Aegis
measured F1 0.672 → 0.927, recall 0.513 → 0.863, TP 76 → 117, FN 57 →
16, FP 2 → 0, speed 468×. But every Phase B rule was built from R6's
misses — including retitles to match classifier keywords — so those are
tuned-corpus numbers that were expected to shrink on fresh code. R7 is
the fresh blind decider: a new 210-project corpus (seed 20261126), the
same frozen protocol, the same factual FP standard, run against the
Phase B build with no further changes. R7 decides whether the Phase B
gain was real or tuning.

**Bottom line up front:** the gain was real. On fresh blind code Aegis
scores F1 0.925 [0.885, 0.959] vs Checkov 0.530 [0.431, 0.616] — a
pairwise lead of +0.397 whose 95% CI [+0.302, +0.500] is entirely above
0 — with recall 0.861 vs 0.361, 125 vs 45 true positives, and 571.5×
faster scans. Aegis leads on **all 8 formats** and **all 4 providers
present**, including on the 165 formats Checkov supports (F1 0.909 vs
0.629 — R6's coverage flip does not recur). The tuned-corpus F1 of 0.927
and the fresh-blind F1 of 0.925 are effectively identical: the Phase B
rules generalized. What R7 does NOT support is the win itself: criterion
(b) fails on a genuine 0–0 tie — both scanners produced zero false
positives in 2,355 adjudicated unmatched findings (1,294 Aegis + 1,061 Checkov), so there is no FP-rate
difference for Aegis to lead. The remaining work is recall on both sides
— 17 Aegis FNs and 78 Checkov FNs — led for Aegis by `secret-hardcoded`
(4), `rds-snapshot-public` (3, a new R7 class), and `az-storage-http-only`
(3, all near-miss).

## 2. Corpus

**210 NEW projects** (ids `r7001`–`r7210`), seed 20261126, 232 project files.

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

Clouds (corpus counts): aws 64, azure 34, multi 22, none 90, **gcp 0**.

- **Freshness verified by hash:** zero SHA-256 overlap vs the R2/R3/R4/
  R5/R6 corpora, 0 within-R7 duplicates.
- **Discrepancy vs protocol §2 (flagged, protocol wins):** the protocol's
  §2 table targets clouds aws ~60, azure ~35, **gcp 1–2**, multi ~24.
  The corpus MANIFEST.json and STATS.json say aws 64, azure 34, multi
  22, none 90, and **gcp 0** — the GCP target was missed entirely (no
  GCP-cloud project exists in the corpus). The aws/azure/multi counts are
  within the protocol's "~" tolerance. The per-provider table in §6.2
  uses the corpus's own counts (aws 64, azure 34, multi 22, none 90);
  there is no GCP row. (R6 had the same class of discrepancy in the
  other direction: protocol aws 60 / gcp 1 vs corpus aws 59 / gcp 2.)
- **Known corpus defects (from `labels/HANDOFF.md`, documented, not
  hidden):**
  - K8s twin-name collisions (r7181, r7183, r7184, r7185, r7194, r7195,
    r7197): two Deployments named `shop-<sfx>` in one file, so findings
    are twin-ambiguous — one twin is vulnerable, the other hardened.
  - Secure-profile projects can contain firm concepts (e.g. literal
    passwords in "secure" RDS billing blocks).
  - Some CFN projects have two template files.
  - Manifest `resource` strings are locator hints only (r7088/r7093
    `az-webapp-no-https` point at the `plan` resource).
  - Labeler-independence limitation (same agent authored generator +
    both labeling passes, procedural independence only) — see §3 and §9.

## 3. Ground truth

- **Two sequential labeling passes (A, then B)** over the generated code,
  both reading code only — never scanner output, never the injection
  plan, never the other pass's file.
- **Labeler-independence limitation (disclosed upfront, protocol §3):**
  the same agent authored the generator and both labeling passes;
  independence is procedural only (Pass B performed without opening Pass
  A's file, using a different implementation) — the same limitation R3–R6
  disclosed. This is NOT personal independence.
- **Agreement (pre-adjudication):** raw agreement **0.9967**, Jaccard
  **0.9934** (Pass A 151, Pass B 150; the single A-only concept is r7015
  `opensearch-tls-old`).
- **Ground truth: 151 firm concepts across 124 projects.** Per-class
  counts (GT): `secret-hardcoded` 44, `sqs-encryption-off` 8,
  `db-public` 8, `redis-non-ssl` 7, `ecr-public-policy` 7,
  `k8s-writable-rootfs` 6, `k8s-allow-priv-esc` 5,
  `compose-cap-add-sys-ptrace` 4, `compose-host-pid` 4, `az-mysql-public`
  2, `az-storage-http-only` 3, `apigw-no-auth` 2, `az-sql-weak-tls` 1,
  `az-vm-password-auth` 1, `cloudfront-origin-http-only` 1,
  `compose-cap-add` 1, `compose-db-port-published` 2,
  `compose-host-network` 1, `compose-privileged` 1,
  `docker-curl-pipe-shell` 1, `docker-multistage-secret` 3,
  `docker-run-as-root` 2, `ec2-imdsv1` 3, `efs-unencrypted` 1,
  `gcp-function-public` 1, `k8s-cap-sys-admin` 3,
  `k8s-cluster-admin-binding` 1, `k8s-ingress-no-tls` 2,
  `k8s-privileged` 2, `k8s-run-as-root` 3, `k8s-seccomp-unconfined` 3,
  `kafka-plaintext` 1, `nsg-rdp-public` 2, `opensearch-no-https` 1,
  `opensearch-tls-old` 1, `rds-snapshot-public` 3, `sg-admin-public` 3,
  `sg-open-ssh` 2, `sns-public-policy` 2, `sqs-public-policy` 3.
- **7 new R7 classes** (declared in the classifier before any scanner
  run, recorded in `labels/CLASSIFIER_CHANGELOG.md`): 4 firm —
  `ec2-imdsv1` 3, `rds-snapshot-public` 3, `sqs-encryption-off` 8,
  `docker-run-as-root` 2; 3 soft — `cloudtrail-off` 3,
  `alb-access-logs-off` 2, `s3-versioning-off` 4. Protocol Addendum 1:
  `ec2-imdsv1` is a renamed revival of the R3/R4 `imdsv1` class, not
  first-ever; the other 6 new classes are genuinely new.
- **FN manifest (sealed, `sealed/fn-manifest.json`):** 179 entries / 178
  unique (project, class) pairs; **122 firm + 53 soft + 3 accounted-for**
  — (r7012, `sg-open-ssh`) naming delta covered as `sg-admin-public`;
  (r7166, `compose-env-file-secret`) naming delta covered as
  `secret-hardcoded`; (r7134, `docker-root`) not a firm concept by
  written reason. **29 GT firm concepts are not in the manifest** (26×
  `secret-hardcoded` + 1× `sg-admin-public` r7012 + 1×
  `opensearch-tls-old` r7015 + 1× `compose-host-network` r7168). Per
  protocol §6, TP is counted against GT (151) and recall/FN against the
  FN manifest (firm denominator 122). The two denominators are different
  by design and must not be conflated: e.g. Aegis's 18 GT
  `secret-hardcoded` TPs outside the manifest-firm set raise precision
  but not the manifest recall (see §5.6).
- **Classifier:** `score_r7.py` taxonomy (R6 table + 7 new R7 classes).
  One mechanical pre-final-scoring fix, documented in
  `labels/CLASSIFIER_CHANGELOG.md`: the FN canonical mapping per
  `labels/adjudication-log.md` §7 (including `compose-cap-add` →
  `compose-cap-add-sys-ptrace` for profiler blocks r7154/r7157/r7160/
  r7170, `compose-cap-add` for debugger r7162; `sg-open-ssh` r7012 and
  `compose-env-file-secret` r7166 deliberately NOT mapped — they stay
  among the 3 accounted-for pairs). Deliberately NO semantic
  title→class mappings added after seeing results (R4 §5.6 precedent):
  near-misses are reported as matcher limitations, not rescored.
- **Scorer verification:** GT sanity 151/151 canonical class present
  (52 multi-mapped, documented in the scorer); FN reconciliation asserts
  pass exactly — 179 entries, 178 unique, 122 firm, 56 non-firm, 29 GT
  extras.

## 4. Scanners

| Scanner | Version | Config | Accuracy | Timing |
|---|---|---|---|---|
| Aegis | 2.3.0, Phase B build (1,148 rules) | `scan <dir> --format=json` | 210/210 | 30×5 |
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

**Infrastructure note:** a sandbox runtime restart at ~16:52 UTC on
2026-11-25 wiped `/tmp` (the Aegis binary and the live sweep logs) and
killed the Checkov accuracy sweep at 63/210 files. The Aegis binary was
rebuilt from the already-checked-out `phase-b/measure-combined` at
`ca5e7f0` (`CGO_ENABLED=0 go build`); the rebuilt SHA-256 **matches the
protocol SHA exactly** (`144a64df…`) and `aegis doctor` again shows
1,148 rules — no code, rules, or branch changed. Aegis outputs (in
`~/workspace`, which survives restarts) were intact. The Checkov sweep
was resumed (resume-safe: existing non-empty outputs skipped) and
completed; wall 1,553 s split across the restart (Aegis wall 3.8 s).
Per-project Checkov exit codes for r7001–r7063 were lost with the log
and are DERIVED in
`scanner-output/checkov/FAILURES-DERIVED-r7001-r7063.json` from output
content (Checkov exits 1 iff ≥ 1 failed check: 59 exit 1, 4 exit 0;
rule validated against all 147 recorded exit codes with 0 mismatches).
Full 210-project split: Checkov 135 exit 1 / 75 exit 0; Aegis 195 exit 1
/ 15 exit 0 (all 210 recorded). No output was empty or unparseable for
either scanner. The only list-form Checkov output is r7022 (terraform +
secrets check types).

## 5. Results

### 5.1 Primary metrics (firm concepts, adjudicated; 95% CIs via cluster bootstrap by project, B=10,000, seed 20261126)

| Scanner | F1 [95% CI] | Precision [95% CI] | Recall [95% CI] | FP rate [95% CI] | FN rate | TP | FP | FN | Findings |
|---|---|---|---|---|---|---|---|---|---|
| **Aegis** | **0.925 [0.885, 0.959]** | 1.000 [1.000, 1.000] | 0.861 [0.794, 0.921] | 0.000 [0.000, 0.000] | 0.139 | 125 | 0 | 17 | 1,419 |
| **Checkov** | 0.530 [0.431, 0.616] | 1.000 [1.000, 1.000] | 0.361 [0.274, 0.445] | 0.000 [0.000, 0.000] | 0.639 | 45 | 0 | 78 | 1,108 |

Factual precision (secondary, (TP+LN)/(TP+FP+LN) over adjudicated
non-hygiene findings): Aegis **1.000 [1.000, 1.000]**, Checkov **1.000
[1.000, 1.000]**. Findings counts are post-hygiene-exclusion (Aegis
1,419 after excluding 40 findings on the 9 protocol §4 hygiene rule
IDs; Checkov 1,108, hygiene-excluded 0 — the §4 hygiene set is Aegis
rule IDs only). TP is counted against GT (151); FN/recall against the
FN manifest (firm 122).

### 5.2 Pairwise differences (95% CI)

| Comparison | Difference [95% CI] | Mean | Entirely >0? |
|---|---|---|---|
| F1 Aegis − Checkov | [+0.3018, +0.5004] | +0.3971 | **Yes** |
| FP rate Checkov − Aegis | [+0.0000, +0.0000] | +0.0000 | **No — exactly 0** |

The F1 lead favors Aegis by +0.397 on the point estimate and the CI's
lower bound is +0.302: the lead is statistically decisive at this corpus
size. The FP-rate difference is exactly zero — both scanners have 0 FPs,
so the CI is a single point at 0 (see §7).

### 5.3 Timing (median of per-project medians)

| Scanner | Median | Per-project median range | Ratio vs Aegis |
|---|---|---|---|
| **Aegis** | **0.01036 s** | 0.0083–0.0136 s | 1× |
| Checkov | 5.9237 s | 4.424–7.107 s | 571.5× slower |

Per-project ratios range 389×–807×, all far above the 2× threshold.

### 5.4 FP adjudication summary

| Scanner | Unmatched | Adjudicated | TP (genuine, labeler-missed) | of which classifier-miss | HYGIENE | LABEL-NOISE | FP |
|---|---|---|---|---|---|---|---|
| Aegis | 1,294 | full (1,294) | 108 | 11 | 152 | 1,034 | **0** |
| Checkov | 1,061 | full (1,061) | 64 | 23 | 5 | 992 | **0** |

Full adjudication of every unmatched finding for both scanners, under
the protocol's FACTUAL FP standard — FP means factually wrong only;
real-but-immaterial/by-design findings are LABEL-NOISE, never FP.
Per-finding verdicts with justifications:
`labels/fp-adjudicated-aegis.json`,
`labels/fp-adjudicated-checkov.json`.

- **Aegis FP = 0.** Every K8s absence rule checked per workload (320
  claim-true; the only 2 block-level candidates, K8S-028/K8S-030 on
  r7176, were confirmed per-container as NOT FP — both target the
  initContainer `setup`, which genuinely lacks `readOnlyRootFilesystem`
  and cap-drop while the main container has both). AWS/Azure/GCP absence
  rules batch-falsified (571 checked, 28 candidates — every candidate
  individually confirmed as a regex over-match: SSE/logging/networkAcls
  belonging to a sibling resource, a `Suspended`/`enabled=false` value,
  or a networkAcls Deny with zero `ipRules` entries, which makes the
  flagged condition factually true), 0 additional FPs. Context-sensitive
  rules (AWS-004, AWS-001, AWS-857, AWS-534, AWS-339, AWS-345, AWS-637,
  AZURE-006/026/105, DOCKER-021, COMPOSE-006, K8S-002, SC-010, AWS-539,
  AWS-710, AWS-204, AWS-443/341, K8S-020, CloudTrail rules, GCP-020/
  204/207/208, DOCKER-032) verified per finding against code. **Both R6
  FPs do NOT recur:** K8S-029 (pod-level seccompProfile) has 0
  claim-false candidates in R7, and DOCKER-005 (HEALTHCHECK NONE) has no
  `HEALTHCHECK NONE` anywhere in the R7 corpus (grep-verified).
- **Checkov FP = 0.** Every K8s finding verified per workload against
  the YAML with the Checkov 3.3.26 source read for the decision-relevant
  checks (K8S_28 passes iff the container drops ALL or NET_RAW; K8S_37
  passes iff it drops ALL; K8S_29 passes on pod-level securityContext
  only; container checks fail per container, so a finding is wrong only
  if every container passes). The first checker run used wrong
  (any-container) falsify logic and was discarded; the corrected run:
  592 claim-true, 0 claim-false, 17 twin-ambiguous (all on
  r7181/r7183/r7184/r7185/r7194/r7195/r7197 — one twin satisfies the
  condition, the finding is on the other twin; NOT FP, per the R6 twin
  doctrine). AWS/Azure/GCP absence rules batch-falsified (83/148 rules
  have patterns; 20 candidates, every one individually confirmed as an
  over-match — e.g. the KMS SSE config belongs to a sibling bucket; the
  `Disabled` matches belong to sibling Key Vaults/storage accounts/SQL
  servers; `POSTGRES_15` is genuinely not the latest major version).
  The 65 rules with no batch patterns were verified individually or via
  the K8s workload report. Checkov source was read where the check's
  semantics were ambiguous (CKV_AZURE_59 inspects `publicNetworkAccess`,
  not blob public access, despite its name; CKV_AZURE_189 passes on
  ipRules/subnet allow-lists — Deny-by-default with no allow-list still
  fails, LABEL-NOISE, same as Aegis AZURE-205). Checkov does NOT repeat
  either Aegis R6 FP: it emits no seccomp finding on r7176, and
  CKV_DOCKER_2 fires only on r7134/r7135/r7139/r7143/r7146, never on a
  `HEALTHCHECK NONE` (none exists in the corpus).
- **Caveat (Aegis TPs, recorded, not rescored):** AWS-001/AWS-341
  findings are counted TP as missing-EXPLICIT-encryption findings. S3/SNS
  apply default encryption since 2023, so the residual risk is about
  explicit config/CMK, not plaintext storage. The same doctrine was
  applied to Checkov's equivalent checks (CKV_AWS_145, CKV_AWS_26).
- **Attribution artifacts (recorded, not rescored):** on r7015 the
  auto-matcher consumed other findings for `opensearch-no-https` /
  `opensearch-tls-old` while the findings that actually identify those
  conditions, CKV_AWS_83 (enforces HTTPS) and CKV_AWS_228 (up-to-date
  TLS policy, Min-TLS-1-0-2019), are in the unmatched set (adjudicated
  TP duplicates). Same pattern: r7205/r7208 privileged (CKV_K8S_37
  consumed, CKV_K8S_16 is the real identifier), r7074 VM password auth
  (CKV_AZURE_1/178 are the real identifiers).

### 5.5 Sensitivity: additive variant and classifier-miss-recovered recall

The primary metrics count TP/FN against the fixed firm universes
(protocol §6). Two sensitivity analyses, both R4/R5 precedent:

**Additive variant** — every adjudicated-TP unmatched finding
additionally counted as a true positive on the GT universe (upper bound;
includes near-duplicates of GT concepts):

| Scanner | Precision | Recall | F1 |
|---|---|---|---|
| Aegis | 1.000 | 0.900 | **0.947** |
| Checkov | 1.000 | 0.507 | 0.673 |

**Classifier-miss-recovered recall** — classifier-miss TPs that
identify a MISSED manifest-firm (project, class) pair count as
recovered recall (the classifier, not the scanner, missed them):

| Scanner | TP_fn | Recovered pairs | Recall (cm) |
|---|---|---|---|
| Aegis | 105 | 8 | **0.926** |
| Checkov | 44 | 18 | 0.508 |

Aegis's recovered 8: r7022 `secret-hardcoded` (AWS-534), r7047/r7054
`sg-admin-public` (AWS-004), r7079/r7080/r7094 `az-storage-http-only`
(AZURE-026), r7094 `az-sql-weak-tls` (AZURE-105), r7133
`secret-hardcoded` (DOCKER-021). Note the 9th Aegis classifier-miss
finding set — AWS-004 on r7012 (`sg-admin-public`, 3 findings, one per
dynamic mgmt port 22/3389/5900) — identifies a GT concept that is a GT
EXTRA, not a manifest-firm pair, so it does not enter the recovered
count (8, not 9). Checkov's recovered 18: r7003/r7040
`rds-snapshot-public` (CKV_AWS_302), r7022/r7173 `secret-hardcoded`
(CKV_SECRET_6), r7057/r7068 `sg-open-ssh` (CKV_AWS_24), r7058
`kafka-plaintext` (CKV_AWS_81), r7094 `az-sql-weak-tls` (CKV_AZURE_52),
r7121/r7136 `docker-run-as-root` (CKV_DOCKER_8), r7192/r7207
`k8s-run-as-root` (CKV_K8S_23/40), r7183/r7184/r7185/r7194/r7195/r7200
`k8s-writable-rootfs` (CKV_K8S_22). Checkov recovers more pairs (18 vs
8) because the keyword classifier misses Checkov's phrasing more often.
Reported primary recall is classifier-mediated recall for both scanners.

### 5.6 False negatives — the FN profile

FN is scored against the FN manifest (firm 122). Aegis missed 17,
Checkov missed 78. Each missed pair was classified as a **near-miss**
(a related finding exists but the keyword classifier did not map it —
reported, NOT rescored) or a **true gap** (no related finding on the
project).

**Aegis — 17 missed (8 near-miss, 9 true gap):**

| Class | Missed | Projects |
|---|---|---|
| `secret-hardcoded` | 4 (2 near-miss, 2 gap) | r7022, r7086, r7087, r7133 |
| `rds-snapshot-public` | 3 (gap) | r7003, r7040, r7102 |
| `az-storage-http-only` | 3 (near-miss) | r7079, r7080, r7094 |
| `db-public` | 2 (gap) | r7044, r7053 |
| `sg-admin-public` | 2 (near-miss) | r7047, r7054 |
| `nsg-rdp-public` | 2 (gap) | r7071, r7078 |
| `az-sql-weak-tls` | 1 (near-miss) | r7094 |

Aegis near-misses (finding exists, doesn't map): AEGIS-AZURE-026
"Storage account allows HTTP traffic" (`az-storage-http-only` ×3);
AEGIS-AZURE-105 "MSSQL server not using TLS 1.2" (`az-sql-weak-tls` ×1,
maps to R4 `weak-tls` only); generic AEGIS-AWS-004 (`sg-admin-public`
×2, R5 condition-relevance principle — r7012's 3 findings are the GT
extra, not a manifest pair); AEGIS-AWS-534 "Secrets in EC2 user_data"
(r7022) and AEGIS-DOCKER-021 (r7133, private-key COPY) for
`secret-hardcoded`. True gaps confirmed by inspecting project outputs:
`rds-snapshot-public` (r7003/r7040: 9–10 findings each, none on the
snapshot's `shared_accounts`; r7102 Pulumi, 0 related findings),
`db-public` (r7044/r7053: DBPassword literals found, but no finding
identifies the public-access condition), `nsg-rdp-public` (r7071/r7078
ARM NSGs), `secret-hardcoded` (r7086/r7087: 0 findings — Bicep
`.bicepparam` secrets, a format-shape blind spot). Aegis's largest
single FN class is `secret-hardcoded` (4 of 17) — but note the
dual-denominator subtlety: Aegis DID detect 32 GT `secret-hardcoded`
concepts (18 of the 26 GT secrets outside the manifest-firm set, plus
14 of 18 manifest-firm ones). Both scanners miss the same 4
`secret-hardcoded` manifest pairs (r7022, r7086, r7087, r7133) — a
shared blind spot, not a differentiator.

**Checkov — 78 missed (18 near-miss, 60 true gap):**

| Class | Missed | Projects |
|---|---|---|
| `secret-hardcoded` | 18 (2 near-miss, 16 gap) | r7011, r7022, r7026, r7044, r7053, r7072, r7086, r7087, r7101, r7105, r7106, r7118, r7125, r7130, r7131, r7132, r7133, r7173 |
| `k8s-writable-rootfs` | 6 (near-miss) | r7183, r7184, r7185, r7194, r7195, r7200 |
| `ecr-public-policy` | 5 (gap) | r7047, r7050, r7052, r7104, r7107 |
| `redis-non-ssl` | 5 (gap) | r7098, r7100, r7106, r7117, r7119 |
| `db-public` | 4 (gap) | r7081, r7082, r7089, r7096 |
| `compose-cap-add-sys-ptrace` | 4 (gap) | r7154, r7157, r7160, r7170 |
| `compose-host-pid` | 4 (gap) | r7155, r7156, r7163, r7172 |
| `rds-snapshot-public` | 3 (2 near-miss, 1 gap) | r7003, r7040, r7102 |
| `docker-multistage-secret` | 3 (gap) | r7122, r7145, r7147 |
| `k8s-run-as-root` | 3 (2 near-miss, 1 gap) | r7176, r7192, r7207 |
| `ec2-imdsv1` | 2 (gap) | r7041, r7061 |
| `sg-open-ssh` | 2 (near-miss) | r7057, r7068 |
| `nsg-rdp-public` | 2 (gap) | r7071, r7078 |
| `apigw-no-auth` | 2 (gap) | r7107, r7113 |
| `docker-run-as-root` | 2 (near-miss) | r7121, r7136 |
| `compose-db-port-published` | 2 (gap) | r7152, r7175 |
| `k8s-ingress-no-tls` | 2 (gap) | r7197, r7198 |
| `cloudfront-origin-http-only` | 1 (gap) | r7032 |
| `kafka-plaintext` | 1 (near-miss) | r7058 |
| `sns-public-policy` | 1 (gap) | r7064 |
| `az-sql-weak-tls` | 1 (near-miss) | r7094 |
| `sqs-public-policy` | 1 (gap) | r7114 |
| `docker-curl-pipe-shell` | 1 (gap) | r7141 |
| `compose-cap-add` | 1 (gap) | r7162 |
| `compose-privileged` | 1 (gap) | r7168 |
| `k8s-cluster-admin-binding` | 1 (gap) | r7187 |

Checkov near-misses: CKV_AWS_302 "DB Snapshots are not Public" (×2,
classifier needs 'snapshot public'/'shared accounts'); CKV_SECRET_6
"Base64 High Entropy String" (r7022 — flags the secret-bearing user_data
heredoc; r7173 — flags the compose env literals); CKV_AWS_24 "no security
groups allow ingress from 0.0.0.0:0 to port 22" (×2, maps to
`sg-open-world` only — title has no "ssh"); CKV_AZURE_52 "MSSQL is using
the latest version of TLS encryption" (r7094, maps spuriously to
`docker-latest`); CKV_DOCKER_8 "Ensure the last USER is not root" (×2,
`USER root` on line 11 after `USER app`); CKV_K8S_23 / CKV_K8S_40
"Minimize the admission of root containers" / "Containers should run as
a high UID" (r7192 Pod + CronJob, r7207 CronJob — explicit runAsUser 0
confirmed per workload); CKV_K8S_22 "Use read-only filesystem for
containers where possible" (×6, one twin explicitly
readOnlyRootFilesystem false confirmed per workload). True gaps: all
Pulumi projects with missed concepts (13 projects) and all Compose
projects with missed concepts (13 projects) — Checkov emitted 0 findings
on them; `secret-hardcoded` (16 gap — Checkov matched ZERO GT
`secret-hardcoded` concepts by auto-match, 0/44); `ecr-public-policy`
(r7047, r7050, r7052, r7104, r7107), `redis-non-ssl` (5, incl. Pulumi
r7106/r7117/r7119), `k8s-ingress-no-tls` (r7197/r7198), `ec2-imdsv1`
(r7041/r7061: only CKV_AWS_79-adjacent IMDS findings, no IMDv1 check),
`cloudfront-origin-http-only` (r7032: only viewer-cert CKV_AWS_174),
`k8s-run-as-root` r7176 (only CKV_K8S_22 fired — the initContainer
`setup` runs as root, but Checkov's container checks do not flag
initContainers there), `docker-curl-pipe-shell` (r7141),
`k8s-cluster-admin-binding` (r7187).

**Both scanners miss 10 manifest-firm pairs** (r7003/r7040/r7102
`rds-snapshot-public`, r7022/r7086/r7087/r7133 `secret-hardcoded`,
r7071/r7078 `nsg-rdp-public`, r7094 `az-sql-weak-tls`). Of those 10,
both recover 1 via classifier-miss (r7094 `az-sql-weak-tls` — AZURE-105
/ CKV_AZURE_52), Checkov alone recovers 3 (r7003/r7040
`rds-snapshot-public`, r7022 `secret-hardcoded`), and 6 are true gaps
for both (r7102, r7086, r7087, r7133, r7071, r7078 — the Bicep
`.bicepparam` secrets, the Pulumi snapshot, and the ARM NSGs are the
shared blind spots).

**Zero for both scanners (by auto-match):** `az-sql-weak-tls` 0/1,
`rds-snapshot-public` 0/3, `nsg-rdp-public` 0/2 — all three are
recovered for at least one scanner only via classifier-miss
(`az-sql-weak-tls` by both; `rds-snapshot-public` by Checkov only;
`nsg-rdp-public` by neither).

## 6. Per-format and per-provider breakdowns

### 6.1 Per-format F1 (primary method; SKIP = scanner natively skips the format)

| Format | Aegis | Checkov |
|---|---|---|
| terraform | **0.923** | 0.833 |
| cloudformation | **0.889** | 0.621 |
| arm | **0.714** | 0.615 |
| bicep | **0.750** | 0.462 |
| pulumi | **0.960** | SKIP (0.000) |
| dockerfile | **0.952** | 0.000 |
| compose | **1.000** | SKIP (0.000) |
| kubernetes | **1.000** | 0.684 |

Aegis leads on every format — the first round in which no format goes
to Checkov. The Phase B fixes show directly: CloudFormation flipped
from R6's 0.385 vs 0.800 (Checkov) to 0.889 vs 0.621 (Aegis), and Pulumi
from 0.556 to 0.960 (the adapter fix: 12/13 manifest-firm, the only miss
r7102 `rds-snapshot-public`). Aegis's weakest formats are now ARM (F1
0.714: recall 0.556, 5/9 manifest-firm — the 4 misses are
`nsg-rdp-public` ×2 and `az-storage-http-only` ×2, the latter all
near-miss) and Bicep (0.750: recall 0.600, 6/10 — misses are
`secret-hardcoded` ×2 (`.bicepparam`) and r7094's two near-misses,
`az-sql-weak-tls` and `az-storage-http-only`). Checkov's Dockerfile precision is undefined (0 TP, 0 FP) with
recall 0.000 (0/11) — same scorer fallback as R6; Checkov matched zero
concepts on Dockerfile despite nominal support (its checks there cover
only soft classes) and zero on Pulumi/Compose by design.

### 6.2 Per-provider F1

| Provider | Projects | Aegis | Checkov |
|---|---|---|---|
| aws | 64 | **0.901** | 0.655 |
| azure | 34 | **0.789** | 0.467 |
| multi | 22 | **0.952** | 0.625 |
| none | 90 | **0.990** | 0.419 |

Aegis leads on every provider, including Azure — the R6 gap (Checkov
0.733 vs Aegis 0.348) is closed and reversed (0.789 vs 0.467), though
Azure remains Aegis's weakest provider (recall 0.652, 15/23
manifest-firm). There is no GCP row: the corpus contains no GCP-cloud
project (§2 deviation). "None" (Compose + Dockerfile + K8s, 90 projects)
is where Aegis's format coverage pays most: F1 0.990 vs 0.419.

### 6.3 Coverage-adjusted view (metrics restricted to formats each scanner natively supports)

| Scanner | Supported projects | F1 | Precision | Recall | FP rate |
|---|---|---|---|---|---|
| Aegis (all 210) | 210/210 | 0.925 | 1.000 | 0.861 | 0.000 |
| Aegis (supported-165 only) | 165/210 | 0.909 | 1.000 | 0.833 | 0.000 |
| Checkov (supported-165 only) | 165/210 | 0.629 | 1.000 | 0.458 | 0.000 |

Restricting both scanners to the 165 formats Checkov supports, Aegis
still leads by 0.280 F1 (0.909 vs 0.629) with recall 0.833 vs 0.458 —
R6's coverage flip does NOT recur (R6: Checkov 0.667 vs Aegis 0.660 on
shared ground). Aegis's overall F1 lead (0.925 vs 0.530) is NOT
coverage-driven this round: on shared ground alone the lead is +0.280,
and the 45 Pulumi + Compose projects add only +0.016 more (Aegis F1
0.960 Pulumi, 1.000 Compose there). Both scanners have precision 1.000
and FP rate 0.000 on the shared set as well.

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

- **(a) Highest F1: PASS.** Aegis F1 0.925 [0.885, 0.959] vs Checkov
  0.530 [0.431, 0.616]. The pairwise difference CI is [+0.3018,
  +0.5004], mean +0.3971 — entirely above 0, so the predeclared rule is
  met with a wide margin. The lead is not coverage-driven (§6.3): on the
  165 shared formats Aegis leads 0.909 vs 0.629.
- **(b) Lowest FP rate: FAIL — GENUINE TIE (CI contains 0, half-width
  < 2pp).** Aegis FP rate 0.000, Checkov FP rate 0.000. The (Checkov −
  Aegis) difference CI is exactly [+0.0000, +0.0000], half-width 0 < 0.02,
  so under the protocol's tie rule this is a genuine tie — and under §1
  a genuine 0–0 tie is a FAIL. Neither scanner has the lowest FP rate,
  because neither scanner has any false positives at all in 2,355
  adjudicated findings. Structural observation (not a rule change, and
  not applied retroactively): with Aegis at 0 FPs, criterion (b) can
  only pass if Checkov produces ≥ 1 FP; on a corpus where both scanners
  are factually perfect, (b) is unpassable by construction. Whether the
  criterion should distinguish "both perfect" from "Aegis worse" is a
  protocol question for a future round, requiring a numbered addendum —
  it cannot change R7's verdict.
- **(c) Fastest: PASS.** Aegis 0.01036 s vs Checkov 5.9237 s — 571.5×
  faster, far above the 2× threshold (per-project ratios 389×–807×).

**Overall: NOT YET.** Two of three criteria pass. This is a new failure
mode: R6 failed (a) on an inconclusive CI and (b) with Checkov ahead on
the point estimate; R7 passes (a) decisively and fails (b) only because
both scanners are at zero false positives.

## 8. Reconciliation: why rounds 2, 3, 4, 5, 6, and 7 differ

| Round | Corpus | Scorer / GT scope | Aegis F1 | Aegis FP rate | Verdict |
|---|---|---|---|---|---|
| 2 | 205 projects, 416 firm concepts | min-counting, full FP adjudication (Aegis/Checkov), 400-samples (KICS/Trivy) | 0.367 [0.323, 0.411] | 0.733 | NOT YET |
| 3 | 210 projects, 150 firm critical/high concepts | same method, narrower GT (critical/high only) | 0.733 [0.674, 0.790] | 0.314 | NOT YET |
| Rescore | SAME 210 projects as R3, same labels/scorer | post-fix regression check | 1.000 | 0.000 | — (regression check) |
| 4 | 210 NEW projects, 136 firm concepts | same method as R3 + 8 new classes, classifier normalization fixes | 0.921 [0.880, 0.955] | 0.000 | NOT YET (KICS FP tie) |
| 5 | 210 NEW projects, 128 firm concepts (closeout) | carried adjudication standard (pre-reconciliation) | 0.141 [0.110, 0.173] | 0.919 | EARNED (under that standard) |
| 6 | 210 NEW projects, 141 GT / 117 manifest-firm concepts | factual FP standard, pre-registered | 0.672 [0.583, 0.747] | 0.026 | NOT YET |
| Phase B (tuned) | SAME 210 projects as R6, same labels | tuned-corpus measurement, NOT blind | 0.927 | 0.000 | — (tuning check) |
| 7 | 210 NEW projects, 151 GT / 122 manifest-firm concepts | factual FP standard, pre-registered | 0.925 [0.885, 0.959] | 0.000 | NOT YET |

Three distinct causes, not one:

1. **Different corpora.** Every round uses a fresh 210-project corpus
   with a different firm-concept universe (416 → 150 → 136 → 128 →
   141 GT / 117 manifest-firm → 151 GT / 122 manifest-firm). The F1
   numbers are not comparable across rounds without this caveat — the
   denominator changed each time, and R7's recall denominator (122
   manifest-firm) is narrower than its TP denominator (151 GT).
2. **Different scorers / adjudication standards.** R5's carried numbers
   (Aegis F1 0.141, point precision 0.090, FP rate 0.919) were computed
   under an adjudication standard that scored real-but-immaterial
   findings as FP. The R5 reconciliation re-verified the carried FP
   verdicts against source and corrected Aegis's precision to 0.79–0.92
   (TP/(TP+FP)) and factual precision to ~0.98 — **never quote R5's
   0.090 without that correction.** R6/R7 use the factual standard from
   the start, so R7's precision (1.000) and FP rate (0.000) are
   comparable to R5's CORRECTED figures (0.79–0.92), not to the carried
   0.090. R5's EARNED verdict was computed under the old standard; the
   correction only improves Aegis's standing, so the verdict stands,
   but its margins are not comparable to R7's.
3. **Tuning and corpus difficulty.** R4's 0.921 was measured on a
   corpus whose classes Aegis's accuracy-100 fixes covered well; R6's
   corpus was harder for Aegis in specific places (Azure ARM/Bicep
   near-misses, CFN public-policy classes, Dockerfile multistage
   secrets) and Checkov was genuinely strong on CFN/ARM/Azure. Phase B
   closed exactly those gaps on the R6 corpus (tuned F1 0.927), and R7
   shows the fixes generalized to fresh code: R7 F1 0.925, statistically
   indistinguishable from the tuned 0.927, with the CFN flip (0.385 →
   0.889) and the Pulumi fix (0.556 → 0.960) both holding on new
   projects. The gap between R6's 0.672 and R7's 0.925 is the Phase B
   work, not a change in corpus difficulty — and R7's corpus is not
   easier for Checkov (its F1 fell 0.564 → 0.530 while Aegis rose).

The honest reading: Aegis v2.3.0 (Phase B build) is a fast, factually
precise scanner (0 FPs in 1,419 findings) whose recall on fresh blind
code is 0.861 — decisively better than Checkov's 0.361, on every format
and every provider, including shared ground. The R4-era near-perfection
claim (0.921) is now reproduced on a fresh corpus (0.925) rather than
being a one-corpus artifact. What R7 does NOT support is the win itself:
criterion (b) requires Aegis to have a strictly lower FP rate than
Checkov, and both are at zero.

## 9. Limitations

- **Single-agent labeling.** Both labeling passes were performed by the
  same agent that authored the generator (procedural, not personal,
  independence) — same limitation as R3–R6, disclosed in protocol §3.
  Class-level agreement was high (Jaccard 0.9934), which bounds but
  does not eliminate labeler bias.
- **Matcher near-misses.** 8 of Aegis's 17 FNs and 18 of Checkov's 78
  FNs are findings that exist but don't map to GT classes (no semantic
  mappings added post-results, by design). Reported recall is
  classifier-mediated recall; the cm-recovered sensitivity (§5.5) puts
  Aegis at 0.926 and Checkov at 0.508.
- **Dual denominators.** TP is counted against GT (151); recall/FN
  against the FN manifest (firm 122). 29 GT firm concepts are not in
  the manifest. Any comparison that mixes the two denominators (e.g.
  reading recall off the TP table) is wrong.
- **Aegis r7012 note.** The AWS-004 classifier-miss set on r7012
  (3 findings) identifies a GT concept that is a GT extra, not a
  manifest-firm pair; the cm-recovered recall counts 8 pairs, not 9.
- **Checkov Dockerfile/Pulumi/Compose precision undefined.** 0 TP and
  0 FP on Dockerfile/Pulumi/Compose; the 0.000 F1s in the per-format
  table are the scorer's fallback, not measured rates. Same for Aegis on
  no format (Aegis has TP > 0 everywhere).
- **Timing-subset interpretation.** Protocol §5's "5 per format group +
  Pulumi both layouts" for 30 projects is ambiguous across 8 formats;
  the 6-group interpretation used is recorded in `timing-subset.json`
  and §4. A different stratification would move the medians slightly;
  the 571.5× ratio makes criterion (c) insensitive to it.
- **Protocol discrepancies (flagged, not silently fixed):** cloud
  counts target gcp 1–2 in §2 vs gcp 0 in the corpus manifests;
  protocol §11 names the report `32_FINAL_EVAL_R7_REPORT.md`, which is
  this file.
- **Checkov accuracy exit codes partly derived, not observed.** The
  per-project exit codes for r7001–r7063 were lost in the 16:52 UTC
  sandbox restart; the 59 exit-1 / 4 exit-0 split is derived from
  failed-check presence in the outputs (see §4), validated with 0
  mismatches against all 147 recorded codes. No output was empty or
  unparseable, so no error exits are hidden in that derivation.
- **Aegis binary rebuilt after a restart, SHA verified.** The binary
  was rebuilt from `ca5e7f0` after `/tmp` was wiped; the rebuilt SHA
  matches the protocol SHA exactly and `aegis doctor` shows 1,148
  rules (see §4).
- **K8s twin ambiguity.** On r7181, r7183, r7184, r7185, r7194, r7195,
  r7197 two Deployments share a name in one file; per-workload
  verification confirms one twin is vulnerable and the other hardened,
  but the finding's resource identity cannot distinguish them. The GT
  concept per project is still counted once. The K8s Checkov checker was
  first run with wrong (any-container) falsify logic, discarded, and
  re-run with source-verified logic (see §5.4).
- **Phase B tuning disclosure.** The 8 Phase B rules (and the Pulumi
  adapter fix) were tuned on R6's misses, including retitles to match
  classifier keywords. R7 is the fresh blind test of that tuning: the
  tuned-corpus F1 (0.927) and the fresh-blind F1 (0.925) agree, which is
  evidence the tuning generalized rather than overfit — but R7 is one
  corpus, and the tuning was aimed at exactly the classes R7 re-tests
  (CFN public policies, Pulumi secrets, Azure TLS/HTTP). A future round
  with new classes would test generalization further.
- **Synthetic corpus.** All 210 projects are generator-built, not real
  repositories. Real-world code has messier shapes (modules, dynamic
  blocks, cross-file references) that this benchmark does not exercise.
- **AWS-001/AWS-341 TP caveat.** Counted as TP for missing EXPLICIT
  encryption; S3/SNS default encryption since 2023 means the residual
  risk is about explicit config/CMK, not plaintext storage (§5.4).

## 10. Reproducible commands

```bash
cd docs/audit/raw/final-eval-r7
python3 sweep_r7.py aegis            # accuracy + timing (Aegis)
python3 sweep_r7.py checkov          # accuracy + timing (Checkov)
python3 score_r7.py                  # auto-scores both scanners
python3 adjudicate_aegis.py          # full Aegis FP adjudication
python3 adjudicate_checkov.py        # full Checkov FP adjudication
python3 stats_r7.py                  # cluster bootstrap (B=10,000, seed 20261126) + decision
```

Raw outputs: `scanner-output/{aegis,checkov}/`
Labels: `labels/` (ground truth, adjudication logs, FP adjudications,
classifier changelog)
Scores: `scores/scores.json`, `scores/stats.json`, `scores/breakdowns.json`
Run log: `RUNLOG.md` (top-level)

## Verdict: NOT YET

Aegis passes (a) highest F1 (0.925 vs 0.530, pairwise CI [+0.302,
+0.500]) and (c) fastest (0.01036 s, 571.5× faster than Checkov) by
decisive margins, and holds factual precision 1.000 with zero false
positives in 1,419 findings. It fails (b) lowest FP rate — not because
it has more false positives than Checkov, but because both scanners have
none: the (Checkov − Aegis) FP-rate CI is exactly [0.000, 0.000], a
genuine 0–0 tie, which §1 scores as a FAIL. Under the pre-registered
all-three win condition, no superiority claim is earned.

What R7 does support, without overclaiming: on this fresh 210-project
corpus, Aegis has the highest F1 by +0.397 (decisive), the fastest scans
by 571.5×, the broadest format coverage, the best per-format F1 in 8 of
8 formats (including 0.909 vs 0.629 on the 165 formats Checkov supports),
zero false positives across 1,419 findings — while finding 2.8× more
true positives than Checkov (125 vs 45) and 2.4× more manifest-firm
concepts (105 vs 44). The Phase B tuning generalized: fresh-blind F1
0.925 vs tuned-corpus 0.927. What it does NOT support: the win itself
(criterion (b) is unpassable when both scanners are at zero FPs), or
parity on Azure/ARM/Bicep recall (Aegis's weakest: ARM recall 0.556,
Bicep 0.600, Azure provider recall 0.652). The remaining work is recall:
17 Aegis FNs, led by `secret-hardcoded` (4 — incl. the Bicep
`.bicepparam` blind spot), `rds-snapshot-public` (3, a new R7 class with
no related Aegis rule), and `az-storage-http-only` (3, all near-miss) —
plus the criterion (b) question for a future protocol addendum.
