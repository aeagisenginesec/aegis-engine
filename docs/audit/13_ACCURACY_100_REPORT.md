# Accuracy to 100% — Mission Report

Branch: `mission/accuracy-100` (from `mission/pulumi-recovery` @ `f7e3cbe`).
Head: `b495abd`. Rule count: 1,146 → **1,151** (+5: AZURE-314, AWS-850, DOCKER-036, K8S-026, K8S-027).

## What "100%" means here

100% on the **defined acceptance sets only**: the 15-control combat corpus,
the round-3 corpus fixtures for the 4 fixed FP classes, and the round-3
ground-truth concepts (150 firm concepts, same labels, same scorer).
This is NOT a claim of universal 100% accuracy on unseen code. The next
fresh blind eval remains a separate future mission; no new eval corpus
was built for acceptance.

## Commits

| Commit | Change |
|---|---|
| `a241e6a` | Terraform parser: attributes after the first on a line |
| `a6ea78f` | Evaluate `jsonencode`/`merge`/`concat` over static args |
| `a95f5df` | Azure SQL coverage (314 weak password, 009 legacy auditing) |
| `1ee7db1` | Gate AWS-005 egress on attachment evidence |
| `3da23be` | Suppress S3 SSE/PAB on intentionally-public buckets |
| `b2d00e1` | DOCKER-002 final-stage scoping; DOCKER-010 first-party registries |
| `3928cbe` | Gaps: AWS-850, CFN Lambda Url, DOCKER-036, K8S-026/027 |
| `b495abd` | GCP-017: exempt forwarding appliances (NAT) |

## Combat corpus: 15/15, 0 FPs

Fixture: `internal/regression/testdata/combat_vuln.tf` (26 resources),
scored by `TestCombat` in `internal/regression/combat_test.go`
(per-control, not raw counts).

Vulnerable controls caught (15/15): `aws_s3_bucket.pub`→002,
`aws_security_group.open`→004, `aws_db_instance.pubdb`→011,
`aws_iam_policy.admin`→006, `aws_ebs_volume.unenc`→009,
`aws_kms_key.norot`→335, `aws_cloudtrail.single`→336,
`azurerm_storage_account.pubst`→AZR-001/AZURE-122,
`azurerm_key_vault.nopurge`→AZR-005, `azurerm_sql_server.weak`→314,
`azurerm_network_security_group.opennsg`→054/244,
`google_storage_bucket.pubb`→GCP-005, `google_compute_firewall.openfw`→002,
`google_sql_database_instance.nolog`→GCP-019, `google_compute_instance.pubvm`→017.
(Baseline at `f7e3cbe` was 12/15; Checkov 13/15.)

Secure controls (11): **0 false positives** on the control negations.
Secure resources legitimately carry other, factually-true hardening
findings (e.g. `privdb` fires backup/Multi-AZ rules; `secb` fires
"without public access prevention" because `public_access_prevention`
really is absent even with UBLA on; `privvm` fires secure-boot/CMEK/
Confidential-VM absent rules). These are logged by the test for
auditability and are not control FPs: they do not claim the control
is violated.

The 3 original combat misses and their fixes:
1. S3 public ACL — parser dropped attributes after the first per line.
2. IAM admin policy — `jsonencode` with comma-less objects was unevaluated.
3. Azure SQL zero findings — no legacy `azurerm_sql_server` coverage.

## Round-3 FP classes: 54 → 0 (before → after, per class)

| Class | Before | After | Fix |
|---|---|---|---|
| AWS-005 by-design egress | 15 | 0 | Fire inline-SG egress only with attachment evidence; standalone rule resources still fire ungated |
| AWS-001/206 on intentionally-public buckets | 24 (12+12) | 0 | Suppress on positive public evidence: public ACL, website config, or public-granting bucket policy |
| DOCKER-002 build-stage root | 8 | 0 | Adapter marks `is_final_stage`; rule skips non-final stages |
| DOCKER-010 `gcr.io` misclassification | 7 | 0 | Trust first-party registries/namespaces (GCR `distroless`/`google-containers`, `registry.k8s.io`, `k8s.gcr.io`, `mcr.microsoft.com`); arbitrary `gcr.io/<project>` still fires |

Verified by re-running the round-3 scorer: all 54 adjudicated FP
instances are gone entirely from the new output (none merely re-matched).

## Round-3 detection gaps: 32 → 0

| Gap | Fix |
|---|---|
| 2× weak DB password (TF) | AWS-850 (heuristic shared with AZURE-314; never carries the value) |
| 3× CFN Lambda Url `AuthType: NONE` | `AWS::Lambda::Url` typemap + `AuthType`→`authorization_type` rename |
| 4× CFN S3 BucketPolicy public principal | CFN converter preserves IAM key casing; policy parsing case-insensitive |
| 5× Pulumi NSG SSH | Already fixed at HEAD (`f7e3cbe`); verified via rescore (054+244 fire) |
| 4× Pulumi Key Vault purge | Already fixed at HEAD; verified via rescore (AZR-005 fires) |
| 5× Docker build tools in final image | DOCKER-036 (final stage only; `curl`/`wget` excluded) |
| 3× K8s secret in env | K8S-026 (literal value + secret-like name; `valueFrom` quiet; values never in findings) |
| 6× K8s no securityContext | K8S-027 (fires only when NO context at pod AND container level) |

## Round-3 rescore (same labels, same scorer, same protocol)

Method: rebuilt binary, re-scanned all 210 projects, ran the frozen
`score.py` from the round-3 eval, then compared unmatched candidates
against the original adjudication by (project, rule, resource, title).
Genuinely new candidates (9) were adjudicated under the documented
round-3 criteria (TP = factually correct finding of a real
weakness/control, incl. duplicates of a GT concept; FP = factually
wrong / by-design / no security value). Full detail in
`docs/audit/raw/accuracy-100/rescore-summary.json`.

| Metric | Before (R3 report) | After (rescore) |
|---|---|---|
| TP (of 150 firm concepts) | 118 | **150** |
| FN | 32 | **0** |
| FP (adjudicated) | 54 | **0** |
| Precision | 0.686 | **1.000** |
| Recall | 0.787 | **1.000** |
| F1 | 0.733 | **1.000** |
| FP rate FP/(TP+FP) | 0.314 | **0.000** |
| Unmatched candidates | 2,028 | 1,983 (all TP/HYGIENE) |

New-candidate adjudication: 5× AZURE-244 → TP (duplicate of the
matched `nsg-open` GT concept; 12 prior 244s were adjudicated TP the
same way); 4× K8S-027 → TP (the DaemonSets genuinely define no
securityContext). During the rescore, 2 additional new FPs appeared
(GCP-017 on NAT instances, surfaced by the parser fix) and were fixed
by a principled exemption (forwarding appliances need a public IP;
the forwarding itself stays flagged) — the numbers above are after
that fix. No bootstrap CIs were recomputed; these are point estimates.

Caveat on the win condition: KICS's round-3 FP rate of 0.000 came from
a 400-finding sample, not full adjudication, so the "lowest FP rate"
comparison is sample-vs-full. On the round-3 corpus with full
adjudication, Aegis FP rate is now 0.000.

## Gates and suites

- Full suite: **32 packages green** (`go test` on all module packages
  except the pre-existing broken docs harness
  `docs/audit/raw/phase6/stage_harness`, two `main` declarations —
  unrelated, untouched).
- Race: green on all changed packages (aws, azure, docker, k8s, gcp,
  terraform + cloudformation adapters).
- Quality gate: **5/5 PASS** — precision 100.0%, recall 100.0%,
  rule-coverage 360/360 critical/high rules with pos+neg evidence,
  performance median 23.3ms / p95 38.6ms (threshold 500ms),
  parser-safety 15/15 explicit.
- SARIF / suppressions / baselines: `TestScanSarifFlag`,
  `TestScanBaselineRoundtrip`, `TestScanInlineSuppression`,
  `TestBaseline_*`, `TestApplyInlineSuppressions*` all pass. The
  fingerprint *algorithm* was not touched; finding *sets* changed
  only where the fixes intend (golden files + parity `expect.json`
  regenerated/updated after verifying each change was the intended
  behavior — see commit notes).
- Performance: R3 corpus scan 2.24s wall vs 2.23s baseline (binary
  startup dominated; no regression). `benchmark/perf_gate.sh` is a
  stub (no benchmark files in `internal/perf`) — the quality-gate
  performance measurement above is the real signal.

## Remaining limitations (honest)

- **054/244 overlap**: two Azure NSG rules fire on the same weakness
  (duplicate findings, adjudicated TP). Dedup debt, not an FP.
- **K8S-027 scope**: fires on any workload with no securityContext
  anywhere, including intentionally-minimal monitoring DaemonSets.
  Factually correct, but noisy for teams that accept that posture.
- **Weak-password heuristic**: guessability, not proof. Word+digits
  shapes, the known-weak list, and length/class floors will miss
  novel weak passwords and may flag unusual-but-strong ones.
- **GCP-017 NAT exemption** keys on `can_ip_forward = true`. A VM
  with forwarding enabled for non-NAT purposes is exempt from 017
  but still flagged by the IP-forwarding rule.
- **Parser recovery** is heuristic (bounded repair loop, 256
  iterations); genuinely malformed files still fall back to the
  strict parse with original diagnostics.
- **Rescore adjudication** of the 9 new candidates was done by the
  implementing agent under the round-3 criteria, not by an
  independent labeler. A fresh blind eval is still needed before
  any general accuracy claim.
- **Parity fixtures**: the two `database-public-azure` Terraform
  fixtures were inequivalent (variable password vs literal in other
  formats); aligned to the literal so formats are equivalent again.

## Merge recommendation

**Recommend merging `mission/accuracy-100` into the parent branch**
after review: all acceptance sets pass, every behavior change is
covered by a regression test, golden/parity updates were verified
individually as intended, and no benchmark gaming was involved (fixes
are detection/correlation improvements, not scorer-specific).
Do not merge on this report alone — the branch is unmerged and the
merge decision is yours.
