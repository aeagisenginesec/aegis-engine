# 03 — Accuracy and Ground Truth

**Mission:** Aegis Independent Competitive Validation — Phase 4 of 10
**Date:** 2026-10-12
**Binary:** `/tmp/aegis-p4`, built from `0c28621` (`fix/demo-defects-d1-d3`), 1,185 rules loaded
**Working tree:** clean (only the tracked `aegis` build artifact modified; ignored per convention)
**Read-only phase:** no rules, adapters, engine, or tests were modified; nothing committed; no branch switch.
Defects found are recorded below, not fixed.

---

## 1. Contamination disclosure (read first)

The accuracy numbers in this report **cannot support claims of independent accuracy**
against an external ground truth, for three reasons:

1. **corpus-v2 (200 projects: 150 dev + 50 held-out) was used during rule development
   and tuning.** Both the fixtures *and* the expected-finding labels were authored
   against the Aegis rule set. The labels enumerate the findings the authors intended
   each fixture to produce — they do not enumerate every semantically-true finding.
   The corpus is Aegis-centric by design.
2. **The AWS demo corpus** (`tests/demos/aws-security-demo/`, 84 fixtures) was built
   alongside the rules and was the direct subject of the D1–D3 defect fixes.
   Its labels cover only the single tested condition per fixture.
3. **The 50 held-out projects were procedurally locked** (secret-seeded stratified
   split; `heldout/manifest.json` sha256 verified intact this phase:
   `089a25fb…0476ddedbe898e` matches `SPLIT.md`), but the lock is procedural, not
   cryptographic — the rule authors work in the same environment, and the fixtures
   and labels share the same Aegis-centric authorship as the dev set.

Consequence: corpus-v2 measures **self-consistency and generalization within the
Aegis rule model**, not independent accuracy. Precision on corpus-v2 is further
depressed by label incompleteness (see §5). The fresh probe in §6 is the closest
thing to an independent check available offline; its limits are documented there.

---

## 2. Metric definitions

All metrics use deduplicated findings: multiple findings with the same
`(rule_id, resource)` collapse to one (highest severity kept).

| Term | Definition |
|---|---|
| **TP** (true positive) | An actual finding whose rule ID **and** resource match an expected finding. Resource match: exact address equality, or type-prefix match when the label gives a bare type (e.g. `aws_s3_bucket` matches `aws_s3_bucket.demo`). |
| **FP** (false positive) | An actual finding with no matching expected finding. |
| **FN** (false negative) | An expected finding with no matching actual finding. |
| **precision** | TP / (TP + FP) |
| **recall** | TP / (TP + FN) |
| **F1** | 2·P·R / (P + R) |
| **critical/high recall** | TP / (TP + FN) restricted to expected findings labeled critical or high |
| **finding-level FP rate** | FP / (TP + FP) (= 1 − precision); raw FP counts and per-project FP also reported |
| **project-level false-alarm rate** | fraction of **secure** projects with ≥ 1 medium-or-higher finding |

**Severity handling.** `info`-severity findings (explicit-uncertainty diagnostics such
as the D3 UNCERTAIN findings) are *excluded* from actionable TP/FP/FN counts and
tallied separately — consistent with the demo post-fix convention that they are not
vulnerability claims. A severity mismatch between a matched finding and its label
still counts as TP; mismatches are listed separately (there were none).

**Scope rule.** Precision/recall are reported *only* where expected findings were
independently enumerated for the measured unit. Everywhere else, only detection
rates are reported (§2 of the task spec).

---

## 3. AWS demo corpus — `tests/demos/aws-security-demo/`

84 fixtures: 34 Terraform vuln/secure pairs + 8 CloudFormation YAML vuln/secure pairs.
Labels cover **only the tested condition** per fixture, so two scorings are given:

- **Scenario-level:** did the tested condition get flagged in the vulnerable fixture?
- **Tested-condition finding-level:** TP = the expected (rule, resource) fired on the
  vulnerable fixture; FN = it did not; FP = the tested rule fired on the tested
  condition in the *secure* fixture. All other findings are out-of-scope context
  (genuine additional issues on other conditions, per the demo report) — counted,
  not scored. Broader finding-level precision/recall is **not computable** here
  (labels not enumerated) and is not reported.

One label nuance: scenario 10's manifest expectation names `AEGIS-AWS-102`, but the
D1 fix implemented detection in `AEGIS-AWS-666`. Both rule IDs are accepted for
scenario 10 (documented in `DEMO_POSTFIX_COMPARISON.md`).

| Format | Vulnerable fixtures (n) | Scenario detection | Tested-condition TP / FN | Tested-condition recall | Tested-condition precision | Secure false flags (n) | Out-of-scope findings (vuln / secure) | Info findings |
|---|---|---|---|---|---|---|---|---|
| Terraform HCL | 34 | **32/34 (94.1%)** | 32 / 2 | 0.9412 | **1.0000** (32/32) | **0/34** | 160 / 142 | 2 / 2 |
| CloudFormation YAML | 8 | **8/8 (100%)** | 8 / 0 | 1.0000 | **1.0000** (8/8) | **0/8** | 43 / 37 | 0 / 0 |

The 2 TF "misses" are scenarios 29/30 (`sns-public-policy`, `sqs-public-policy`):
the D3 UNCERTAIN info diagnostic fires (analyst is told to review), but no
*actionable* finding is produced — scored here as `UNCERTAIN-VISIBLE`, not as a
silent miss. There are **zero silent misses** on the tested conditions post-fix,
and **zero false flags** on any of the 42 secure fixtures' tested conditions
(the D2 false positive is eliminated).

Out-of-scope context: the vulnerable TF fixtures carry 160 additional actionable
findings on *other* conditions (e.g. an S3-ACL fixture also lacking encryption);
the secure TF fixtures carry 142. These were not adjudicated finding-by-finding in
this phase and are excluded from the scored metrics by design.

---

## 4. corpus-v2 — dev (150) vs held-out (50)

Format coverage: **Terraform HCL only** (all 200 projects are `.tf`; no
CFN/ARM/Bicep/Pulumi/Docker/K8s projects exist in corpus-v2).

### 4.1 Strict finding-level results (primary metric)

| Split | Projects (vuln/secure) | Expected findings | TP | FP | FN | Precision | Recall | F1 | FP rate |
|---|---|---|---|---|---|---|---|---|---|
| dev | 150 (105/45) | 120 | 119 | 320 | 1 | **0.2711** | **0.9917** | 0.4258 | 0.7289 |
| held-out | 50 (35/15) | 40 | 40 | 65 | 0 | **0.3810** | **1.0000** | 0.5517 | 0.6190 |

| Split | Critical/high recall | Recall by expected severity | Severity mismatches | Project false-alarm rate |
|---|---|---|---|---|
| dev | **64/65 = 0.9846** | high 0.9833, critical 1.0, medium 1.0, low 1.0 | 0 | **0/45 = 0.0** |
| held-out | **21/21 = 1.0000** | high 1.0, critical 1.0, medium 1.0, low 1.0 | 0 | **0/15 = 0.0** |

The single dev FN is `v2-134` (`edge-for-each-unencrypted`): expected
`AEGIS-AWS-007` high on `aws_db_instance.dbs`. The file was **skipped entirely**
(`files_parsed: 0`) because of a `for_each` with an unresolvable expression; a
warning diagnostic was emitted but no finding produced. Recorded as **P4-DEF-02**
(§7). No other expected finding was missed on either split, and no matched finding
disagreed with its labeled severity.

### 4.2 Why strict precision is low — and what it actually means

The FP pool is dominated by **semantically-true findings the labels never
enumerated**, not by wrong findings. Top extra-firing rules (dev+held-out):

| Rule | n | Severity | Title | Semantically true on fixture? |
|---|---|---|---|---|
| AEGIS-AWS-667 | 33 | low | IAM role has no permissions boundary | yes |
| AEGIS-AWS-673 | 33 | low | IAM role has no description | yes |
| AEGIS-AWS-683 | 18 | low | EC2 instance without termination protection | yes |
| AEGIS-AWS-699 | 18 | low | EC2 instance without Nitro Enclaves enabled | yes |
| AEGIS-AWS-677 | 18 | low | IAM policy statement has no Sid | yes |
| AEGIS-AWS-692 | 15 | low | EC2 instance without an IAM instance profile | yes |
| AEGIS-AWS-706 | 14 | low | RDS instance on the default option group | yes |
| AEGIS-AWS-501 | 8 | critical | IAM policy allows privilege escalation | yes (co-fire on `*:*` admin policies) |
| AEGIS-AWS-503 | 7 | high | IAM policy allows data exfiltration primitives | yes (co-fire) |
| AEGIS-AWS-502 | 7 | critical | Privilege escalation via iam:PassRole on * | yes (co-fire) |

~90% of extra findings are low-severity hygiene rules firing truthfully on minimal
synthetic fixtures. Because the labels were authored to enumerate only the intended
finding per project, strict finding-level precision here is a **lower bound on true
precision**, not a measurement of it.

Secondary metric — **actionable (medium+) precision**, excluding low/info findings
from the FP pool (lows are hygiene signal, not the security-relevant claim):

| Split | TP (med+) | FP (med+) | Actionable precision |
|---|---|---|---|
| dev | 113 | 65 | **0.6348** |
| held-out | 38 | 10 | **0.7917** |

The remaining medium+ extras are likewise predominantly true co-fires
(501/502/503/504 on admin policies; 696 root-volume encryption; 820 Athena SSE-KMS;
840 plaintext target group; 657 group inline policy). A full adjudication was not
performed on corpus-v2; the probe in §6 does it on fresh material.

**Held-out vs dev:** recall 1.000 vs 0.9917, critical/high recall 1.000 vs 0.9846,
actionable precision 0.7917 vs 0.6348 — no degradation on the locked set within
these sample sizes. (Caveat §1: the lock is procedural and the corpus is
Aegis-centric, so this is a consistency check, not an independence proof.)

---

## 5. Fresh accuracy probe (16 new projects, 7 formats, 3 clouds)

Fixtures and labels were authored for this phase and **never used in rule
development**. Each expected finding was labeled *before scanning*, from reading
the rule's Go source (rule ID, severity, trigger condition); the `basis` field of
each label in `probe_manifest.json` cites the code path. Fixture content (names,
values) is new.

| # | Project | Format | Cloud | Vuln? | Labeled expected findings |
|---|---|---|---|---|---|
| p4-01 | aws-tf-vuln | terraform-hcl | AWS | yes | AEGIS-AWS-002 high, AEGIS-AWS-001 high, AEGIS-AWS-004 high |
| p4-02 | aws-tf-secure | terraform-hcl | AWS | no | — |
| p4-03 | azure-tf-vuln | terraform-hcl | Azure | yes | AEGIS-AZURE-006 high, AEGIS-AZURE-119 high |
| p4-04 | azure-tf-secure | terraform-hcl | Azure | no | — |
| p4-05 | azure-arm-vuln | arm-json | Azure | yes | AEGIS-AZURE-007 high |
| p4-06 | azure-arm-secure | arm-json | Azure | no | — (Deny present; rule path returns nil) |
| p4-07 | gcp-tf-vuln | terraform-hcl | GCP | yes | AEGIS-GCP-002 high, AEGIS-GCP-001 critical |
| p4-08 | gcp-tf-secure | terraform-hcl | GCP | no | — |
| p4-09 | k8s-vuln | kubernetes-yaml | k8s | yes | AEGIS-K8S-001 critical, AEGIS-K8S-002 high |
| p4-10 | k8s-secure | kubernetes-yaml | k8s | no | — |
| p4-11 | docker-vuln | dockerfile | docker | yes | AEGIS-DOCKER-001 med, -002 high, -003 high, -004 low |
| p4-12 | docker-secure | dockerfile | docker | no | — |
| p4-13 | cfn-json-vuln | cloudformation-json | AWS | yes | AEGIS-AWS-004 high |
| p4-14 | compose-vuln | docker-compose | docker | yes | AEGIS-COMPOSE-001 high |
| p4-15 | bicep-vuln | bicep | Azure | yes | AEGIS-AZURE-007 high |
| p4-16 | pulumi-vuln | pulumi-yaml | AWS | yes | AEGIS-AWS-002 high |

### 5.1 Strict results

| Metric | Value | Denominator |
|---|---|---|
| TP / FP / FN | 18 / 84 / **0** | 18 labeled expected findings |
| Precision (strict) | **0.1765** | 18/102 |
| Recall | **1.0000** | 18/18 — every labeled finding fired, all 7 formats |
| F1 (strict) | 0.3000 | |
| Critical/high recall | **16/16 = 1.0000** | |
| Project false-alarm rate | **5/6 = 0.8333** | 6 secure projects |

### 5.2 Adjudicated results (auditor review of all 84 extras)

Every extra finding was reviewed against its fixture. Classification:

- **83 of 84 extras are semantically true** — the finding's claim is factually
  correct (e.g. K8S-007 high fired on the `hostNetwork: true` the fixture really
  has; GCP-014 medium on the genuinely internet-open SSH rule; the Azure strict-
  default findings on genuinely-unset attributes — the `allow_nested_items_to_be_public`
  provider default of `true` was verified against provider docs).
- **1 of 84 is a genuine false positive** → **P4-DEF-01** (§7): `AEGIS-AZURE-187`
  (high) fired on the *secure* ARM Key Vault (p4-06) whose
  `networkAcls.defaultAction` is `"Deny"`.

Adjudicated precision: **(18 + 83) / (18 + 84) = 101/102 = 0.9902**.
The strict-vs-adjudicated gap is label incompleteness, same as corpus-v2 — on
fresh material, with the auditor's own labels, the same pattern reproduces.

### 5.3 The 5/6 "false alarms" on secure fixtures — read carefully

The probe's secure fixtures are *minimal* (they harden only the labeled
conditions), not comprehensive. The medium+ findings on them are almost all true
claims about unset attributes (no flow logging, no TLS-deny policy, no resource
limits, no managed identity, no private endpoint). The informative comparator is
corpus-v2's 60 comprehensive secure projects: **0.0 false-alarm rate**. The probe's
5/6 measures noise on minimal fixtures, not alarm rate on hardened infrastructure.
The one genuine FP among them is P4-DEF-01.

### 5.4 Probe limits (honest)

- Labels were derived by reading Aegis rule logic, so the probe measures
  **rule-implementation correctness on new inputs**, not independent ground truth;
  a rule that is wrong in the same way for every input would still score well.
- 16 projects / 18 labeled findings is small; confidence intervals are wide
  (rule-of-three: 0/18 misses → 95% upper bound on miss rate ≈ 15%).
- Secure fixtures are minimal, inflating apparent alarm rates (§5.3).
- No adversarial inputs (unknown values, cross-file references, modules) beyond
  one ARM expression; edge-case behavior is covered by corpus-v2's edge projects.

---

## 6. Defects recorded (not fixed — read-only phase)

**P4-DEF-01 (new, high) — AEGIS-AZURE-187 false positive on ARM/Bicep Key Vault
with `networkAcls.defaultAction: "Deny"`.**
The ARM adapter preserves nested property key casing (`defaultAction`); the rule's
`blockString` lookup uses exact snake_case (`default_action`) → not found → fires
with evidence `default_action = ""`. Reproduced on ARM JSON (p4-06) in the fresh
probe. Terraform path unaffected (users write snake_case). Sibling rule
AEGIS-AZURE-007 returns nil on the same input (no FP, but no confirmation either).
Likely a systemic pattern for any rule reading nested ARM properties (e.g. storage
`networkAcls`). Needs a regression test on the ARM adapter/rule boundary.

**P4-DEF-02 (new, high) — `for_each` with unresolvable expression skips the whole
file, silently dropping an expected high finding (corpus-v2 `v2-134`).**
Expected `AEGIS-AWS-007` high on an unencrypted `aws_db_instance.dbs` was missed:
`files_parsed: 0`, `resources_scanned: 0`. A *warning* diagnostic is emitted, so it
is not fully silent — but the skip reason text claims the resource was "analyzed
as a single instance", which contradicts the outcome (nothing was analyzed).
`count`-based resources (`edge-count-insecure`) parse and hit correctly, so this
is specific to `for_each`. Candidate fix direction (not applied): single-instance
fallback analysis as the message already promises, with a regression test.

Neither defect existed in the D1–D3 set; both were found by Phase 4 measurement.

---

## 7. Uncertainty discussion

1. **Label completeness dominates precision.** On all three corpora, strict
   finding-level precision (0.18–0.38) is driven by true-but-unlabeled findings,
   not by wrong findings (adjudicated probe precision 0.99). Any future accuracy
   claim must either enumerate complete expected sets or report adjudicated
   precision with a documented review protocol — never raw counts.
2. **Recall is the stronger number here.** 18/18 probe, 119/120 dev, 40/40
   held-out, 32/34 demo (2 uncertainty-visible, 0 silent). The one genuine miss
   (P4-DEF-02) is an adapter skip, not a rule-logic miss.
3. **No raw finding counts are used as accuracy proxies anywhere in this report.**
   (Counts appear only as sample-size denominators and out-of-scope context.)
4. **Severity fidelity is perfect on labeled data:** 0 severity mismatches across
   159 matched findings (corpus-v2) + 18 (probe).
5. **Sample sizes are small.** The probe's 18 findings and the demo's 42 scenarios
   cannot support tight confidence bounds; corpus-v2's 160 labeled findings are
   the largest sample but are contaminated (§1).
6. **Format coverage is uneven.** corpus-v2 is TF-only; ARM/Bicep/Pulumi/Docker/
   Compose/K8s accuracy rests on the 16-project probe plus the parity audit
   (Phase 2/3), not on labeled corpora.

---

## 8. What a truly independent evaluation would need

1. **Externally-authored ground truth:** fixtures and expected findings written by
   people who have not seen the Aegis rule set, ideally seeded from real-world
   vulnerable IaC (e.g. sampled public Terraform/CloudFormation with disclosed
   CVEs or incident reports), with complete per-fixture expected-finding
   enumeration by ≥2 independent labelers and inter-rater agreement reported.
2. **Cryptographic held-out:** fixtures generated and hashed by a third party,
   revealed only at scoring time.
3. **A fixed competitor baseline on the same labels** (Checkov/KICS/Trivy scored
   against the *same* expected sets, with their rule→label mapping published),
   so "Aegis vs X" is a comparison of accuracy rather than of rule counts.
4. **Adjudication protocol** for extra findings (true-positive-by-semantics vs
   false positive), published before scoring, to avoid post-hoc reclassification.
5. **Adversarial slice:** unknowns, cross-file refs, modules, `for_each`/`count`,
   dynamic blocks — the shapes where P4-DEF-02-class misses live.
6. **Scale:** hundreds of labeled findings per format for usable confidence
   intervals.

---

## 9. Reproduction

```bash
cd ~/workspace/aegis-engine
git log -1 --format=%H          # 0c28621 (fix/demo-defects-d1-d3)
export PATH=~/workspace/toolchain/go/bin:$PATH
go build -o /tmp/aegis-p4 ./cmd/aegis/

# corpora scoring (raw JSON per project + summary.json)
python3 docs/audit/raw/phase4/score_phase4.py

# fresh probe (fixtures + auditor labels + scorer)
python3 docs/audit/raw/phase4/probe/score_probe.py
```

Raw data: `docs/audit/raw/phase4/` —
`score_phase4.py`, `summary.json`, `demo_*.json`, `corpus2_dev_*.json` (150),
`corpus2_heldout_*.json` (50), `stdout.txt`;
`probe/` — 16 fixture projects, `probe_manifest.json` (labels + code-path basis),
`score_probe.py`, `probe_results.json`, `raw_p4-*.json` (16).

No source files were modified, staged, or committed in this phase; no branches
were switched. The held-out manifest hash was verified intact before scoring.
