# AWS Demo Post-Fix Comparison — D1, D2, D3

**Fix branch:** `fix/demo-defects-d1-d3`
**Pre-fix commit:** `a35878e` (AWS security detection demonstration)
**Post-fix binary:** built from fix-branch HEAD
**Original evidence preserved:** `docs/audit/AWS_DEMO_REPORT.md`, `docs/audit/demo-raw/`,
`docs/audit/00_DEMO_BASELINE.md` were NOT modified. Post-fix raw outputs:
`docs/audit/demo-raw-postfix/`.

Determinism: 3 consecutive post-fix full-corpus scans byte-identical
(SHA-256 `96c4133e…` ×3).

## Summary counts

| Corpus | Pre-fix findings | Post-fix findings | Delta |
|---|---|---|---|
| TF vulnerable (34 files) | 197 | 200 | +3 net |
| TF secure (34 files) | 145 | 146 | +1 net |
| CFN vulnerable (8 files) | 51 | 51 | 0 |
| CFN secure (8 files) | 37 | 37 | 0 |

## Every changed finding, explained

### Vulnerable corpus (+4 added, −1 removed)

| Change | Rule | Resource | Explanation |
|---|---|---|---|
| + | AEGIS-AWS-666 (high) | `aws_iam_role.demo` via `managed_policy_arns` | **D1 fixed.** Scenario 10 (`managed_policy_arns = [AdministratorAccess]`) now detected. Was a silent miss. |
| + | AEGIS-AWS-343 (info) | `aws_sns_topic_policy.demo` | **D3 fixed.** Scenario 29 policy contains unresolvable `aws_sns_topic.demo.arn` reference → explicit UNCERTAIN diagnostic instead of silent skip. |
| + | AEGIS-AWS-344 (info) | `aws_sqs_queue_policy.demo` | **D3 fixed.** Scenario 30, same as above. |
| + | AEGIS-AWS-307 (high) | `aws_lambda_function.demo`, attr `kms_key_arn` | **D2 evidence corrected.** Still fires on the vulnerable fixture (no KMS), but the evidence attribute path is now the real top-level `kms_key_arn` instead of the non-existent `environment.kms_key_arn`. |
| − | AEGIS-AWS-307 (high) | `aws_lambda_function.demo`, attr `environment.kms_key_arn` | Replaced by the corrected finding above. Same scenario, correct attribute path. |

### Secure corpus (+2 added, −1 removed)

| Change | Rule | Resource | Explanation |
|---|---|---|---|
| + | AEGIS-AWS-343 (info) | `aws_sns_topic_policy.demo` | D3: secure fixture also uses an unresolvable resource reference. UNCERTAIN info diagnostic is correct — it does NOT claim a vulnerability, only that the policy could not be fully evaluated. Not a false positive (info severity, excluded from actionable counts). |
| + | AEGIS-AWS-344 (info) | `aws_sqs_queue_policy.demo` | Same as above. |
| − | AEGIS-AWS-307 (high) | `aws_lambda_function.demo` | **D2 false positive eliminated.** The secure fixture sets top-level `kms_key_arn` correctly; the rule no longer fires. High-severity FP count on secure corpus: −1. |

### Net security effect

- **True positives gained:** +1 (D1 scenario 10, high severity)
- **Silent misses converted to visible uncertainty:** +2 (D3 scenarios 29/30, info)
- **False positives eliminated:** −1 (D2 on secure fixture 22, high severity)
- **Evidence accuracy fixed:** 1 (D2 attribute path)
- **Unrelated regressions:** 0 — every other finding is byte-identical pre/post.

## Scenario-level detection (Terraform)

| Metric | Pre-fix | Post-fix |
|---|---|---|
| Vulnerable scenarios detected | 31/34 (91.2%) | 32/34 (94.1%), of which 2 are UNCERTAIN-visible |
| Secure controls incorrectly flagged (actionable) | 1/34 | 0/34 |

Scenarios 29/30 are counted as "visible" rather than "detected": the public-principal
pattern cannot be confirmed because the policy references an unresolvable ARN, but the
analyst is now explicitly told to review — versus the previous silent miss.

## Residual limitations

- D3 UNCERTAIN fires whenever a policy's `Resource` (or other leaf) references a
  computed value (e.g. `aws_sns_topic.demo.arn`). This is honest but will be common
  in real code; all such findings are info severity and excluded from quality-gate
  precision/recall.
- D1 matches on ARN name substring `administratoraccess` (case-insensitive),
  consistent with the pre-existing rule behavior. Customer-managed policies with
  "AdministratorAccess" in the name would fire — same as before the fix.
- D2 still requires an `environment` block with variables before checking KMS;
  functions without env vars are out of scope (unchanged behavior).
