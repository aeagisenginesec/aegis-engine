# Remediation Safety

## Safety Classifications

Every auto-fix is classified by risk:

| Fixer | Rule | Action | Classification | Rationale |
|-------|------|--------|----------------|-----------|
| 001 | AEGIS-AWS-001 | Insert S3 encryption block | **SAFE** | Additive only, no existing config changed |
| 002 | AEGIS-AWS-002 | ACL public → private | **CONDITIONAL** | Could break legitimate public buckets |
| 007 | AEGIS-AWS-007 | RDS storage_encrypted = true | **SAFE** | Encryption is always safe to enable |
| 008 | AEGIS-AWS-008 | RDS deletion_protection = true | **SAFE** | Prevents accidental deletion |
| 009 | AEGIS-AWS-009 | EBS encrypted = true | **SAFE** | Encryption is always safe to enable |
| 010 | AEGIS-AWS-010 | CloudTrail log validation = true | **SAFE** | Logging improvement, no behavior change |
| 011 | AEGIS-AWS-011 | RDS publicly_accessible = false | **CONDITIONAL** | Could break intentional public DB |
| 012 | AEGIS-AWS-012 | Insert S3 versioning block | **SAFE** | Additive only, no existing config changed |

### Classification Definitions

- **SAFE**: Auto-apply without review. The fix cannot break legitimate configurations.
- **CONDITIONAL**: Requires human review. The fix is usually correct but could break intentional setups.
- **MANUAL**: Never auto-applied. Requires explicit human decision.

### Blocked Resource Types

The following are **never** auto-fixed (require `--force`):

**IAM** (authorization decisions):
- `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_group_policy`, `aws_iam_user_policy`
- `aws_iam_role` (trust policy controls role assumption)

**Networking** (reachability decisions):
- `aws_security_group`, `aws_security_group_rule`
- `aws_vpc_security_group_ingress_rule`, `aws_vpc_security_group_egress_rule`
- `aws_network_acl`

**Rationale:** A wrong auto-fix on IAM can lock out workloads or widen access.
A wrong auto-fix on networking can cause outages. These need human judgment.

## Safety Guarantees

Every fixer is audited against three guarantees:

### (a) Minimal Diff
- `boolFixer`: replaces exactly one attribute line, or inserts one line
- `blockFixer`: inserts exactly one nested block before the closing brace
- Nothing is reformatted, no adjacent lines touched
- Aborts (proposes nothing) on any span mismatch — never corrupts

### (b) Patched Output Re-parses
- `ValidatePatch` applies every patch to an isolated temp copy
- Re-scans the patched copy
- Rejects if: target resource no longer parses, or new error diagnostics appear

### (c) No IAM/Networking Touch
- Each fixer hard-matches `res.Type` against safe types only
- `ProposeAll` skips blocked types unless `--force`
- Type-level backstop guards future fixers

## Dry-Run Default

`aegis fix` runs in dry-run mode by default. No files are written unless
`--apply` is explicitly passed. Every proposed patch shows a diff for review.

## Regression Tests

Per-fix safety tests in `internal/remediation/safety_regression_test.go`:
- `TestFixer001_Safety`: minimal diff, preserves tags, adds encryption block
- `TestFixer002_Safety`: only fires on known public ACL values
- `TestFixer007_Safety`: rule ID verification
- `TestFixer011_Conditional`: documents CONDITIONAL classification
- `TestBlockedResourceTypes_Comprehensive`: all 10 blocked types verified
- `TestDefaultFixers_AllHaveTests`: all 8 fixers accounted for

## Re-scan After Fix

`ValidatePatch` re-scans the patched Terraform and verifies:
1. The original finding is resolved
2. No NEW findings were introduced by the patch
3. The file parses without errors
