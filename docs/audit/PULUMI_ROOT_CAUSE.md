# Pulumi Coverage Recovery — Root-Cause Report

**Date:** 2026-10-13
**Branch:** `mission/pulumi-recovery`
**Commit:** `41a8d77`
**Trigger:** Round-2 evaluation (205 projects) — Aegis emitted **zero findings** on all 15 Pulumi YAML projects (c056–c070).

## Root cause

The Pulumi adapter (`internal/adapter/pulumi/pulumi.go`) only read program
sections (`resources:`, `variables:`, `configuration:`) at the **document
root**. All 15 evaluation fixtures — and a large share of real-world
Pulumi YAML — nest these sections under **`template:`** (the legacy/embedded
program layout):

```yaml
name: finance-storage
runtime: yaml
template:          # <-- adapter ignored everything under here
  configuration: ...
  resources: ...
```

Result: `Parse` found no `resources:` section → warning diagnostic →
0 resources → 0 findings. The adapter was technically "working" (it emitted
a warning), but the warning was wrong: these *are* valid Pulumi programs.

The official Pulumi YAML reference documents top-level `resources:` as the
modern layout, but the `template:`-nested layout remains common in the wild
(all 15 blind-authored fixtures used it). Supporting only one layout was the
defect.

## Secondary defects found during investigation

1. **Azure storage property names**: Pulumi `azure-native` uses different
   property names than the Terraform attribute names the rules expect.
   A "secure" fixture (c058) fired 16 findings for controls it had actually
   set. Fixed mappings:
   - `minimumTlsVersion` → `min_tls_version`
   - `supportsHttpsTrafficOnly` → `https_traffic_only_enabled`
   - `allowSharedKeyAccess` → `shared_access_key_enabled`
   - `publicNetworkAccess` (enum `Enabled`/`Disabled`) → boolean
     `public_network_access_enabled`
   - `networkRuleSet` → `network_rules`
   
   After fix: 16 → 11 findings on c058; all remaining are genuine gaps in
   the fixture (no versioning, no private endpoint, etc.), not adapter errors.

2. **Typemap gaps**: 5 resource types used by the eval fixtures had no
   typemap entry (fell back to sanitized derivation + warning):
   - `aws:ec2:NetworkAclRule` → `aws_network_acl_rule`
   - `azure-native:authorization:RoleAssignment` → `azurerm_role_assignment`
   - `azure-native:resources:ResourceGroup` → `azurerm_resource_group`
   - `azure-native:sql:FirewallRule` → `azurerm_mssql_firewall_rule`
   - `azure-native:storage:BlobContainer` → `azurerm_storage_container`

## Fix summary (commit 41a8d77)

- `programNode()`: use the `template:` mapping when the root defines no
  `resources:` of its own. Root layout takes precedence if both exist.
  An `info` diagnostic discloses which layout was used.
- `config:` accepted as alias for `configuration:` (modern reference name).
- Azure storage property normalization (table above) via `renameAttr`.
- 5 typemap entries added.
- 6 new regression tests (18 total in package, all pass).

## Before/after (15 eval fixtures)

| Project | Profile | Before | After | Correct? |
|---------|---------|--------|-------|----------|
| c056 | vuln S3 | 0 | 7 (4 crit/high incl. exfil path) | ✅ |
| c057 | vuln EC2 | 0 | 13 | ✅ |
| c058 | secure Azure | 0 | 11 (0 resolved-by-fix FPs) | ✅ |
| c059 | mixed RDS | 0 | 14 | ✅ |
| c060 | mixed KV | 0 | 3 | ✅ |
| c061 | mixed Lambda | 0 | 8 | ✅ |
| c062 | vuln NSG | 0 | 4 (2 high: RDP open) | ✅ |
| c063 | secure IAM | 0 | 3 (0 crit/high) | ✅ |
| c064 | mixed SQL | 0 | 15 | ✅ |
| c065 | mixed VPC | 0 | 2 | ✅ |
| c066 | vuln storage | 0 | 22 (5 high) | ✅ |
| c067 | secure Lambda | 0 | 5 (0 crit/high) | ✅ |
| c068 | vuln KV | 0 | 3 (2 high) | ✅ |
| c069 | secure RDS | 0 | 8 (1 high: IAM auth) | ✅ |
| c070 | mixed multi | 0 | 22 | ✅ |

Secure fixtures (c058, c063, c067, c069) produce zero critical/high
findings except one legitimate hardening gap (c069: RDS IAM auth).
Vulnerable fixtures fire the expected rules.

## Known limitations (not fixed)

- **Partial string interpolation** (`"${var}-suffix"`) is not resolved;
  pure `${var}` references are. Documented; values stay literal (safe).
- Pulumi programs in TypeScript/Python/Go/.NET remain out of scope
  (requires language runtimes; documented in `docs/PULUMI.md`).
- `fn::*` intrinsics become explicit Unknown (by design, with warning).

## Coverage matrix

| Area | Status |
|------|--------|
| Layout: top-level `resources:` | ✅ supported (existing) |
| Layout: `template:`-nested | ✅ fixed this commit |
| `variables:` / `configuration:` / `config:` | ✅ both layouts |
| `${...}` pure references | ✅ resolved |
| `fn::*` intrinsics | ⚠️ explicit Unknown + warning (by design) |
| TS/Python/Go/.NET programs | ❌ out of scope (documented) |
| Azure storage property normalization | ✅ fixed this commit |
| Typemap (eval fixture types) | ✅ 25/25 covered |
