# ARM Template & Bicep Support

**Status:** Implemented · **Date:** 2026-10-12 · **Adapters:** `internal/adapter/arm`, `internal/adapter/bicep`

## Strategy

Zero new rules. Both adapters convert ARM/Bicep into the canonical IR using
Terraform-style resource types (`azurerm_*`) and snake_case attributes, so
all **313 Azure rules** apply automatically.

## ARM Templates (`internal/adapter/arm/`)

### Detection

`Handles()` sniffs `.json` file content for the ARM deployment template
`$schema` marker (`deploymentTemplate.json`). Registered **before**
`manifests.Adapter` in `defaultAdapters()` (which claims every `.json`).
Non-ARM JSON falls through to the manifests adapter unchanged.

### Type mapping (`typemap.go`)

80+ ARM types → Terraform types, e.g.:

| ARM type | Terraform type |
|---|---|
| `Microsoft.Storage/storageAccounts` | `azurerm_storage_account` |
| `Microsoft.KeyVault/vaults` | `azurerm_key_vault` |
| `Microsoft.Sql/servers` | `azurerm_mssql_server` |
| `Microsoft.ContainerService/managedClusters` | `azurerm_kubernetes_cluster` |
| `Microsoft.Network/networkSecurityGroups/securityRules` | `azurerm_network_security_rule` |
| `Microsoft.Web/sites` | `azurerm_app_service` |

Longest-prefix matching resolves child types through their parents.
Unmapped types become `arm_<sanitized>` with a warning diagnostic (no
rules apply, but the resource is visible, never silently dropped).

### Property mapping

ARM `properties` are flattened onto the resource with camelCase →
snake_case conversion, plus per-type renames where Terraform names differ:

| ARM property | Terraform attribute |
|---|---|
| `allowBlobPublicAccess` | `allow_blob_public_access` |
| `minimumTlsVersion` | `min_tls_version` |
| `supportsHttpsTrafficOnly` | `https_traffic_only_enabled` |
| `enablePurgeProtection` | `purge_protection_enabled` |
| `softDeleteRetentionInDays` | `soft_delete_retention_days` |
| `minimalTlsVersion` (SQL) | `minimum_tls_version` |
| `publicNetworkAccess` | `public_network_access_enabled` |
| `enableRbac` (AKS) | `role_based_access_control_enabled` |

Top-level `location`, `tags`, `kind`, `sku`, `identity` are also mapped.
`Microsoft.Storage/storageAccounts/blobServices` is folded into its parent
as a `blob_properties` block so versioning rules apply.

### Template functions

A recursive-descent evaluator resolves where static:

| Function | Behavior |
|---|---|
| `parameters('x')` | Default value, or Unknown when none |
| `variables('y')` | Recursive evaluation with cycle guard |
| `concat(...)`, `format(...)` | Evaluated when all args known |
| `toLower/toUpper/replace/split/join` | Best-effort on known strings |
| `string/int/bool/createArray/coalesce` | Best-effort conversions |
| `resourceId()`, `reference()`, `listKeys()` | Unknown (not statically knowable) |
| `subscription()`, `resourceGroup()` | Unknown |
| `if()`, `equals()`, `guid()`, `uniqueString()` | Unknown |
| `copy` loops on resources | Warning diagnostic, resource skipped |

Anything unparseable or unresolvable becomes an explicit `Unknown` value —
never guessed. `[[` escape handled.

## Bicep (`internal/adapter/bicep/`)

No `bicep` CLI dependency. A lightweight parser handles the common subset:

```bicep
param location string = 'westeurope'
var kvName = '${storageName}-kv'

resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageName
  location: location
  properties: {
    allowBlobPublicAccess: true
  }
}
```

- `param` → ARM parameters (with defaults); `var` → ARM variables
- `resource sym 'Type@apiVersion' = {...}` → ARM resource (apiVersion stripped)
- `@decorators` skipped; `existing` resources skipped with warning (not managed)
- `for`-loop resources skipped with warning (not expanded)
- `module`, `output`, `targetScope` skipped with warning
- String interpolation `'${a}-x'` → `[concat(parameters('a'), '-x')]`
- Ternary → `[if(...)]` (evaluator returns Unknown)
- Child resources via `parent:` get `parent/child` naming with static-name resolution

The parsed Bicep is translated to ARM-equivalent structures and fed to
`arm.BuildResources`, so all ARM semantics (functions, typemap, renames)
apply uniformly.

## CLI integration

- `cmd/aegis/main.go`: `arm.New(), bicep.New()` registered before
  `manifests.Adapter` in `defaultAdapters()`
- `internal/discovery`: `.bicep` added to discovered extensions

## Verification

- `go build ./...`, `go vet`, `gofmt` clean
- `go test ./internal/adapter/arm/ ./internal/adapter/bicep/` — 30 tests pass
  (8+ vulnerable/secure template pairs per format for Storage, Key Vault,
  SQL, AKS; expression/param/var/interpolation/loop/parent tests)
- Full suite: 32 packages green
- `aegis quality-gate`: **PASS (5/5)**
- End-to-end: ARM + Bicep in one directory scan correctly; existing Azure
  rules fire on converted resources (29 findings on the smoke-test fixtures)

## Known limitations

- ARM `copy` loops and Bicep `for` resource loops are not expanded
  (explicit warning, resource skipped)
- Bicep `module` references are not followed
- `existing` Bicep resources are skipped (not managed by the template)
- Unmapped ARM types get no rule coverage (warning diagnostic emitted)
