# Adapter IR Mapping — ARM, Bicep, Pulumi

Semantic-parity audit notes for three Aegis adapters. Read-only documentation;
no code was modified. All citations are `file` → `function`/symbol.

Repo: `~/workspace/aegis-engine/` (Go module `aegis`).
IR contract: `internal/ir/ir.go` — `Resource{Type, Name, Provider, Attributes map[string]Value, Span}`,
`Value{Raw, Known, Span, Ref}`. Design rules that matter here: unresolved values are
explicit (`Known == false`), never zero-values; `Ref` holds a dotted path when the
value is an unresolved *reference*; "Known is always false when Ref is set".

Registration order (relevant to detection) — `cmd/aegis/main.go` `defaultAdapters()`:
`terraform, planjson, compose, pulumi, arm, bicep, cloudformation, manifests, dockerfile`.
The manifests adapter claims every `.json`/`.yaml` file, so `pulumi` and `arm` must
(and do) precede it. ARM additionally excludes `*.plan.json` so the planjson adapter wins.

---

## 1. ARM adapter (`internal/adapter/arm/`)

Source: `arm.go` (916 lines), `typemap.go` (282 lines).

### 1.1 Entry point & detection

- `Adapter.Handles(path)`: extension must be `.json` (case-insensitive), path must not
  end in `.plan.json`, **and** the first 64 KiB of the file (read from disk via
  `looksLikeARM`/`readBounded`, not from the `src` bytes handed to `Parse`) must contain
  `deploymenttemplate.json` case-insensitively — i.e. the `$schema` marker. Content
  sniffing exists because manifests claims every `.json` file.
- `Adapter.Parse(path, src)`: `json.Unmarshal` into `map[string]any`, then
  `BuildResources(path, tmpl)`. Malformed JSON → **error** diagnostic
  (`arm: invalid JSON in %s: %v`); the adapter never returns a hard Go error for
  content problems ("content problems never produce a hard error" — `Parse` comment).
- `BuildResources` is **exported** so the Bicep adapter reuses it after translating
  Bicep into ARM-equivalent structures (§2). Type/attribute/expression semantics below
  therefore apply identically to Bicep input.

### 1.2 Type mapping

- `typemap.go` → `armTypeTable`: **93 entries** mapping ARM types to Terraform-style
  canonical types, e.g. `Microsoft.Storage/storageAccounts` → `azurerm_storage_account`.
- `normalizeType(armType)`: exact match first, then **longest-prefix match** on
  `/`-separated segments — a child type not in the table inherits its parent's type.
  E.g. `Microsoft.Storage/storageAccounts/blobServices` (no exact entry) resolves via
  `Microsoft.Storage/storageAccounts` → `azurerm_storage_account`, `mapped=true`.
- Fallback for unmapped types: `arm_` + lowercased type with `/`, `.`, `-` → `_`
  (e.g. `Microsoft.Resources/deployments` → `arm_microsoft_resources_deployments`),
  `mapped=false` → **warning** diagnostic
  `arm: unmapped resource type %q; emitted as %q (no rules apply)`. The resource is
  kept visible; "no rules apply" because rule packs key on canonical types.
- `Provider` is always the literal `"azure"`.
- `Name`: `ctx.eval(rdm["name"])`; if it doesn't resolve to a known string, falls back
  to the raw string, then to `"unnamed"`.
- Resources are sorted by type+name (`sort.SliceStable`) for deterministic output.

### 1.3 Attribute mapping

`evalCtx.mapResource` maps, in order:

1. Top-level fields: `location`, `tags`, `kind`, `sku`, `identity` — each `eval`'d.
   Derived conveniences: `sku.name` → `sku_name`, `identity.type` → `identity_type`
   ("Rules sometimes read sku as a plain string").
2. `properties` object flattened into attributes. Each key goes through
   `propertyRenames(tfType)` — **13 switch cases covering 15 canonical types**
   (one case covers `azurerm_app_service`/`azurerm_linux_web_app`/`azurerm_windows_web_app`) —
   mapping ARM names to the exact Terraform attribute names the Azure rule pack expects
   (e.g. `networkAcls` → `network_rules`, `supportsHttpsTrafficOnly` →
   `https_traffic_only_enabled`, `allowBlobPublicAccess` → `allow_blob_public_access`).
   Anything not renamed goes through generic `snake()` (camelCase→snake_case;
   acronym runs treated as one word: `CidrIp` → `cidr_ip`).
3. A property that would clobber an already-set top-level field is skipped
   ("Avoid clobbering top-level fields already set").

Nested structures: objects → `map[string]ir.Value`, arrays → `[]ir.Value`, recursively
`eval`'d. Per the IR doc comment, nested blocks are `[]Value` of `map[string]Value`
or `map[string]Value` — the adapter follows that.

Special case: `foldBlobServices` merges a `blobServices` child into its parent storage
account as a `blob_properties` block. **This function is dead code — see §1.7.**

### 1.4 Expression resolution

`evalCtx.eval` + a hand-written recursive-descent parser (`exprParser`) for `[…]`
expressions. `isExpression` requires leading `[` (not `[[`, the literal-bracket escape,
handled by `unescapeBracket`) and a trailing `]`; parse failures → `Unknown`.

**Resolved statically (in `callFunc`):** 20 function names — `parameters`, `variables`,
`concat`, `format`, `tolower`, `toupper`, `replace`, `string`, `int`, `bool`,
`createarray`, `coalesce`, `empty`, `length`, `contains`, `startswith`, `endswith`,
`split`, `join`, `first`/`last` — plus string/number/bool literals and `.prop` /
`['k']` / `[n]` navigation over *known* maps/lists (`navigate`, `navigateIndex`).
Matching is case-insensitive (`strings.ToLower(name)`).

**Parameters/variables:** `parameters('x')` resolves to the parameter's `defaultValue`
(evaluated, may itself reference params/variables); **parameters without defaults are
Unknown by design**. `variables('x')` evaluates lazily with a cycle guard
(`varStack`); cycles or missing variables → Unknown.

**Become explicit Unknown (`Known:false`, no `Ref` set):** everything else, including
`if`, `equals`/`not`/`and`/`or`, `reference`, `listKeys`/`list*`, `resourceId`,
`subscriptionResourceId`, `tenantResourceId`, `extensionResourceId`, `providers`,
`deployment`, `subscription`, `resourceGroup`, `environment`, `guid`, `uniqueString`,
`newGuid`, `utcNow`, `createObject`, `union`, `intersection`, `json`, `base64`,
`range`, `copyIndex`, and any infix operators (`==`, `&&` — the grammar has no
operators, so they fail parsing → Unknown). Navigation on unknown or wrong-typed
bases stays Unknown. `null` literal → Unknown. JSON `nil` → Unknown.

⚠️ **Parity note:** `reference()` and `resourceId()` are among the most common ARM
functions in real templates (keys, endpoints, IDs); they always become Unknown with
**no `Ref` recorded** — the information that "this was a reference to X" is lost,
unlike the Pulumi adapter which preserves the path in `Ref` (§3.4).

### 1.5 Uncertainty policy

Unknowns are explicit and never guessed (`callFunc` comment: "Anything not explicitly
handled returns Unknown (never guessed)"). The ARM adapter **never sets `Value.Ref`** —
unresolved references are bare `Known:false`. Rules must treat them as "cannot decide".

### 1.6 Diagnostics

Warnings (`t.diag("warning", …)`):
- `arm: resource entry is not an object; skipped` — entry dropped.
- `arm: resource %q uses a copy loop which is not expanded; skipped` — **whole
  resource skipped** (explicitly "never silently half-expanded").
- `arm: resource without type; skipped` — dropped.
- `arm: unmapped resource type %q; emitted as %q (no rules apply)` — kept as fallback type.

Errors: invalid JSON (`arm: invalid JSON in %s: %v`).

**Silently skipped (no diagnostic) — flagged:**
- **Nested `resources:` arrays inside a resource object are silently dropped.**
  `BuildResources` iterates only the top-level `tmpl["resources"]`; `mapResource`
  never reads a nested `resources` key. Inline child resources (a common ARM authoring
  style, e.g. subnets inside a virtual network, blobServices inside a storage account)
  vanish without a word.
- `condition` — a conditionally-deployed resource is treated as unconditionally
  deployed (false-positive risk for rules on resources that may not exist).
- `dependsOn`, `apiVersion`, `scope`, `zones`, `plan`, `extendedLocation` — not mapped.
- Nested deployments (`Microsoft.Resources/deployments`): emitted as the fallback
  type with a warning, but the inner `properties.template.resources` is **never
  recursed into** — an entire nested template's resources are lost.
- Variable-level `copy` loops and property-level `copy` blocks: not expanded; they
  degrade to Unknown values with no diagnostic.

### 1.7 Known gaps / bugs

1. **`foldBlobServices` is unreachable (dead code) — blobServices children are
   mistyped.** The fold checks `r.Type` against `"arm_Microsoft.Storage/storageAccounts/blobServices"`
   (mixed case — but the `normalizeType` fallback lowercases everything, so this
   string can never be produced) and `"azurerm_storage_account_blob_services"`
   (which `normalizeType` never emits — no table entry, and the fallback is
   `arm_`-prefixed). Meanwhile longest-prefix matching maps
   `Microsoft.Storage/storageAccounts/blobServices` → **`azurerm_storage_account`
   with `mapped=true` (no warning)**. Net effect: a blobServices child becomes a
   bogus duplicate storage account; the intended `blob_properties` fold (versioning,
   delete-retention, change-feed) never runs, so rules keyed on those attributes
   cannot fire. Latent secondary bug: `byAddr` indexes the unfiltered `resources`
   slice but the result is applied to the filtered `out` slice (`parent := &out[pi]`),
   which would panic on certain orderings if the fold ever fired.
2. No nested-resource handling (§1.6) — the biggest resource-loss gap.
3. `Handles` sniffs only the first 64 KiB for the `$schema` marker; a template whose
   `$schema` appears later (unusual key ordering in a large file) is not claimed and
   falls through to the manifests adapter. `Handles` also re-reads the file from disk
   rather than using the `src` bytes `Parse` receives.
4. Expression grammar has no operators, no lambda functions, no multi-line-string
   awareness; `json.Number` handling in `eval` is dead (encoding/json yields float64
   without `UseNumber`).

---

## 2. Bicep adapter (`internal/adapter/bicep/`)

Source: `bicep.go` (858 lines). No typemap — it reuses the ARM adapter's.

### 2.1 Entry point & detection

- `Adapter.Handles(path)`: file extension `.bicep` (case-insensitive) only. **No
  content sniffing.** `.bicepparam` (Bicep parameter files) are **not** handled by any
  adapter — parameter values that could resolve Unknowns are never read.
- `Adapter.Parse(path, src)`: hand-written recursive-descent `parser` builds an
  ARM-template-equivalent `map[string]any` (injecting the `$schema` itself), then
  calls `arm.BuildResources(path, tmpl)` and appends both diagnostic lists.
- Strategy (package comment): don't shell out to the bicep CLI; parse the common
  subset and translate non-static expressions into ARM `[…]` expression strings so the
  ARM evaluator resolves what it can. **All type/attribute/expression semantics of §1
  are inherited verbatim** — this is parity by construction between ARM and Bicep,
  for the subset the parser accepts.

### 2.2 Type mapping

The resource type string `'type@apiVersion'` is parsed by `parseTypeString`; the
`@apiVersion` suffix is stripped (`armType`) and the ARM type flows into
`arm.BuildResources` → `normalizeType`. Same 93-entry table, same longest-prefix
rule, same `arm_` fallback + warning. `Provider` is `"azure"` (inherited).

### 2.3 Attribute mapping

`parseResource` builds the ARM resource map:
- `name` from the body, else the symbolic name (`rmap["name"] = sym` fallback).
- Keys copied through: `location`, `kind`, `sku`, `tags`, `properties`, `identity`,
  `zones`, `dependsOn`, `plan`, `extendedLocation`, plus any other top-level body keys.
  The ARM `mapResource` then drops `zones`/`dependsOn`/`plan`/`extendedLocation`
  (and `condition`) silently, exactly as for native ARM input.
- `parent: someRes` → name joined as `"parent/child"` by `joinParentChild`: plain
  string concat when both sides are static, otherwise an ARM
  `[concat(parentFrag, '/', childFrag)]` expression.
- Property-name conversion is the ARM layer's: per-type `propertyRenames` + generic
  `snake()`. Bicep's own syntax uses the same camelCase property names as ARM, so
  this is consistent.

### 2.4 Expression resolution

Bicep values are translated to either static Go values or ARM expression strings
(`tval{v, isExpr}`), via `parseExpr` → `parseTernary` → `parsePrimary`:

- **String interpolation** `'${a}-suffix'` → `[concat(variables('a'), '-suffix')]` by
  `interpolate`; the ARM evaluator then resolves it or marks Unknown.
- **Identifiers** (`identFrag`): `param` → `parameters('x')`, `var` →
  `variables('x')`, resource symbol → the resource's translated *name* when statically
  known (so `parent:` references produce readable child names), otherwise `unknown()`;
  any other identifier → `unknown()`. Suffixes `.prop` / `['k']` / `[n]` are appended
  textually; the ARM evaluator navigates them (unknown base → Unknown).
- **Ternary** `c ? a : b` → `[if(c, a, b)]` — ARM has no `if()` in `callFunc`, so this
  **always becomes Unknown** (explicit, no diagnostic).
- **Function calls** (`parseCall`): translated verbatim to `[name(args)]`; the ARM
  evaluator resolves only its 20 functions (§1.4), the rest → Unknown. Note Bicep
  built-ins like `resourceId`, `subscriptionResourceId`, `uniqueString`,
  `guid`, `pickZones`, `toObject`, `items` all land as Unknown.
- **Objects passed as function arguments** degrade to `unknown()` (`armLit`: "Objects
  can't be ARM literals; mark unknown"). Arrays become `createArray(...)` fragments
  or static `[]any` with embedded ARM-expr strings (which the ARM layer evaluates
  element-wise).
- Literals: `'...'` (with `''` escape), `'''...'''` multiline strings, numbers, bools,
  `true`/`false`/`null` (`null` → ARM `null` → Unknown, consistent with §1.4).
- Decorators (`@description(…)`, `@secure()`, …) are consumed by `skipDecorator`
  **with no diagnostic**.

⚠️ **Silently degraded (flagged):** property-level `[for …]` comprehensions are *not*
detected (only the top-level resource `= [for …]` form is). Inside an array/object,
`for` parses as an unknown identifier and the comprehension degrades into an array
of Unknown values **with no diagnostic** (traced through `parseArray`/`parseExpr`).
⚠️ String escape bug: in `parseStringVal`, `\n` → literal `n` (the code writes the
char after the backslash verbatim instead of interpreting `\n`/`\r`/`\t`); `\$`
→ `$` happens to be correct for interpolation escaping.

### 2.5 Uncertainty policy

Same as ARM: explicit Unknown, never guessed. Non-static Bicep becomes an ARM `[…]`
string; the ARM evaluator marks what it can't resolve Unknown. The sentinel
`[unknown()]` (`unknownExpr()`) guarantees Unknown for untranslatable constructs.
`Value.Ref` is **never set** by the Bicep path (it goes through ARM string
expressions) — unlike Pulumi, the reference *path* is not preserved.

### 2.6 Diagnostics

Warnings (all prefixed `bicep: `, all file-level span line 1):
- `statement %q is not supported; skipped` — for `module`, `output`, `import`,
  `using`, `targetScope`, `func`, `type`. **A skipped `module` means the module's
  resources never appear in the scan** — transitive closure is lost with only this
  warning.
- `resource %q uses a for-loop; not expanded, skipped` — whole resource dropped.
- `resource %q is 'existing' (not managed); skipped` — the symbol is not registered,
  so references to it become `unknown()`.
- `resource %q missing type string` / `missing =` / `body is not an object`,
  `var %q missing =`, `unexpected token %q; skipped`.

**Silently skipped (flagged):** decorators (no diagnostic at all); property-level
`for` comprehensions (§2.4); the `\n`-escape mishandling; `targetScope` semantics
beyond the warning.

### 2.7 Known gaps

1. `module` references: not inlined — any resources defined in modules are invisible.
   (By design per the package comment, but it is the largest Bicep coverage gap.)
2. `for` loops: resource-level skipped with warning; property-level silently Unknown.
3. `existing` resources skipped — cross-references to existing infrastructure are Unknown.
4. User-defined `func`/`type`, `import`, `using`, `targetScope` — skipped.
5. `.bicepparam` files not parsed — parameter defaults that would resolve Unknowns are missed.
6. Resource-symbol references resolve only to the resource's **name**
   (`identFrag`/`resName`); property access like `st.properties.allowBlobPublicAccess`
   or `st.id` appends suffixes onto a name literal and the ARM evaluator yields
   Unknown. So cross-resource property references are always Unknown (explicit, at least).
7. All ARM-layer gaps apply (§1.7): the blobServices mistyping, `condition`/`dependsOn`
   drops, no nested-deployment recursion. (Nested `resources:` arrays don't exist in
   Bicep syntax — children are separate statements with `parent:` — so the §1.6
   nested-array drop does not apply to Bicep input; but the resulting blobServices
   child is still mistyped as `azurerm_storage_account` via longest-prefix match.)

---

## 3. Pulumi adapter (`internal/adapter/pulumi/`)

Source: `pulumi.go` (353 lines), `typemap.go` (240 lines).
Scope (package comment): **declarative Pulumi YAML only**; TypeScript/Python/Go/.NET
programs are out of scope — see `docs/PULUMI.md`.

### 3.1 Entry point & detection

- `Adapter.Handles(path)`: basename (case-insensitive) exactly `pulumi.yaml` or
  `pulumi.yml`. Must precede manifests (it does — 4th in `defaultAdapters()`).
- `Adapter.Parse(path, src)`: `yaml.Unmarshal` into a `yaml.Node` tree (span-preserving:
  `spanOf` uses `n.Line`/`n.Column` — **the only one of the three adapters with real
  per-resource spans**; ARM/Bicep spans are file-level line 1).
- Invalid YAML → **error** diagnostic (`pulumi: invalid YAML: %v`), no hard error.
  Non-mapping document root → warning + skip; missing `resources:` section → warning
  (`pulumi: %s has no resources: section; nothing to scan`).

### 3.2 Type mapping

- `typemap.go` → `pulumiTypeTable`: **152 entries** of
  `<package>:<module>:<Type>` → `(canonical type, provider)`, covering AWS classic
  (`aws:…`), `azure-native:…`, and `gcp:…` tokens.
- `normalizeType(token)`: exact match, else fallback `pulumi_` + `sanitizeToken`
  (non-alphanumerics → `_`, lowercased) with provider inferred from the first token
  segment (`aws`→aws, `azure-native`/`azure`→azure, `gcp`→gcp, else `"pulumi"`).
  Unmapped non-empty token → **warning**
  (`pulumi: resource %q has unmapped type %q; using fallback type %q (some rules may not apply)`).
- ⚠️ A resource entry **without** a `type` key gets type `"pulumi_"` with **no
  diagnostic** (the warning is guarded by `typeStr != ""`). Silent-ish.
- ⚠️ `aws-native:*` tokens are not in the table and the provider inference only
  matches segment `"aws"` exactly, so they fall back with provider `"pulumi"`.
- `Name` is the **YAML logical name** (the key under `resources:`), never the physical
  name property — see parity note §4.5.

### 3.3 Attribute mapping

- `properties:` keys → `toSnake` (unicode-aware camelCase→snake_case:
  `serverSide` → `server_side`, `HTTPServer` → `http_server`, SCREAMING → lowercase;
  already-snake names pass through). Applied recursively to nested maps.
- **No per-type renames** (unlike ARM's `propertyRenames`). Property names are purely
  mechanical conversions, so where Terraform attribute names diverge from
  snake_cased provider names, rules miss. Concrete divergence vs ARM: ARM maps
  `networkAcls` → `network_rules`; Pulumi yields `network_acls`.
- `options.*` (`protect`, `ignoreChanges`, `dependsOn`, `provider`, `parent`,
  `aliases`, `deleteBeforeReplace`, …) are **dropped with no diagnostic**; the code
  comment says protect/ignoreChanges are "intentionally not mapped" as "metadata, not
  security signals" — but `dependsOn`/`parent`/`provider` edges are lost silently too.

### 3.4 Expression resolution

`parser.value` / `scalar` / `resolveRef`:

- **`${…}` references are recognized only when the *entire* scalar is `${…}`**
  (`parseRef`: `len>3 && HasPrefix "${" && HasSuffix "}"`). Resolution order:
  1. `variables:` / `configuration:` defaults (collected by `collectVars`; config
     `{type:, default:, secret:}` form uses `default`; **secret without default is
     absent → unknown**) — the referenced node's value is inlined recursively via
     `p.value`, so refs-to-refs resolve.
  2. A head matching a logical resource name → **Unknown-with-`Ref`** (`Ref` = the
     full ref body, e.g. `"mybucket.arn"` — dotted-path style, matching the IR contract).
  3. Unknown name → Unknown-with-`Ref` (ref recorded).
- **fn::* intrinsics**: a single-key mapping whose key starts with `fn::` →
  **warning** (`pulumi: intrinsic %q is not statically resolvable; treated as unknown`)
  + `Known:false` with `Ref` = the intrinsic name (e.g. `"fn::secret"`).
  ⚠️ Note: this `Ref` is an intrinsic name, not a dotted reference path — a slight
  deviation from the IR doc comment ("Ref holds its dotted path").
- ⚠️ **Embedded interpolation is NOT resolved (flagged):** `"prefix-${var}-suffix"`
  fails `parseRef` (not the whole string) and is kept as a **Known string containing
  the literal text `${var}`**. Rules comparing names/ARNs/endpoints see unresolved
  template text presented as ground truth — worse than Unknown.
- YAML aliases (`AliasNode`) are resolved transparently.
- Multi-document YAML: only the first document's mapping is used (`nodeMap` unwraps
  one `DocumentNode`); additional documents are ignored silently.

### 3.5 Uncertainty policy

Unresolvable → explicit `Known:false`, never guessed. Unlike ARM/Bicep, Pulumi
**preserves the reference path in `Ref`** for unresolved `${}` refs — strictly more
information for a later semantics pass. `!!null` → `UnknownValue`.

⚠️ **Bool parsing bug (confirmed against yaml.v3 v3.0.1 `resolve.go`):**
`scalar` does `Raw: n.Value == "true"` for `!!bool` nodes, but yaml.v3 preserves the
original literal in `Node.Value` while tagging `True`/`TRUE` as `!!bool` (resolve.go
line 52: `{"true", "True", "TRUE"}`). So `flag: True` / `flag: TRUE` become
**`Known:true, Raw:false`** — a wrong value, not an Unknown. (Also `!!int` via
`fmt.Sscanf(n.Value, "%d")` misparses hex like `0x10` as 0 — edge case, no diagnostic.)

### 3.6 Diagnostics

- Error: `pulumi: invalid YAML: %v`.
- Warnings: non-mapping document root (`… is not a Pulumi program …; skipped`),
  missing `resources:` section, `resource %q is not a mapping; skipped`, unmapped type
  (see §3.2), `intrinsic %q is not statically resolvable; treated as unknown`.
- **Silently skipped (flagged):** all of `options.*`; empty-type fallback; embedded
  `${}` left as literal Known strings (§3.4); the `True`→`false` bug (§3.5);
  additional YAML documents; stack settings files (`Pulumi.<stack>.yaml` — config
  values live there in real projects, so configuration refs usually stay unknown).

### 3.7 Known gaps

1. Only Pulumi YAML; all imperative language SDKs out of scope.
2. No per-type property renames — mechanical `toSnake` only (§3.3 divergence example).
3. No stack config files read → most `configuration:` refs are unknown in practice.
4. No `dependsOn`/`parent`/`provider` edges (dropped silently).
5. `fn::invoke` (data sources), `fn::secret`, `fn::toJSON`, etc. all → Unknown
   (with warning, at least).
6. `getResource`-style lookups don't exist in YAML; n/a.

---

## 4. Cross-format parity risks (audit summary)

| # | Risk | Detail |
|---|------|--------|
| 1 | **Nested ARM children vanish; Bicep/Pulumi equivalents survive** | ARM JSON with inline nested `resources:` arrays silently drops those children (§1.6). The same infrastructure authored in Bicep (separate statements + `parent:`) or Pulumi keeps them. Resource-count divergence across formats for identical infrastructure. |
| 2 | **`foldBlobServices` dead → blobServices mistyped in ARM *and* Bicep** | Longest-prefix matching types `…/blobServices` as `azurerm_storage_account` (no warning); the intended `blob_properties` fold never executes (§1.7). ARM↔Bicep parity holds (both wrong), but versioning/delete-retention/change-feed rules can't fire in either. |
| 3 | **Attribute-name divergence ARM/Bicep vs Pulumi** | ARM/Bicep apply 15-type `propertyRenames` (e.g. `networkAcls`→`network_rules`); Pulumi applies only mechanical `toSnake` (`networkAcls`→`network_acls`). Same Azure resource, different attribute keys → rules fire in one format, not the other. |
| 4 | **Reference fidelity: Pulumi keeps `Ref`, ARM/Bicep don't** | Pulumi unresolved `${res.attr}` → `Known:false` + `Ref:"res.attr"`. ARM `[reference(…)]` / Bicep `st.id` → bare `Known:false`. A semantics pass can resolve Pulumi refs later; ARM/Bicep refs are information-theoretically lost. |
| 5 | **Resource `Name` semantics differ** | ARM/Bicep `Name` = deployment name expression (physical-ish); Pulumi `Name` = YAML logical key. `Resource.Address()` (`type.name`) will not match across formats for the same infrastructure — cross-format finding correlation by address is unreliable. |
| 6 | **Embedded `${}` in Pulumi stays a Known literal** | `"prefix-${var}-suffix"` is Known with raw `${var}` text (§3.4) — rules see template syntax as data. ARM/Bicep interpolation always goes through the expression evaluator (Unknown when unresolvable). |
| 7 | **`True`/`TRUE` → `false` in Pulumi** | Wrong Known value, not Unknown (§3.5) — the most dangerous uncertainty failure: a rule *can* decide, incorrectly. |
| 8 | **`condition` ignored (ARM/Bicep)** | Conditionally-deployed resources are treated as always deployed → potential false positives with no diagnostic. Pulumi YAML has no equivalent construct. |
| 9 | **Span fidelity differs** | Pulumi: real line/col from `yaml.Node`. ARM: file-level span (line 1) — `encoding/json` discards positions. Bicep: file-level span (hand parser doesn't track positions). Evidence `Span`s are comparable only for Pulumi. |
| 10 | **Module/nested-template boundaries** | Bicep `module` → warning + full skip of the module's resources; ARM nested deployments → fallback type + inner template never recursed (§1.6). Both lose transitive resources, with different diagnostics. |
| 11 | **Unmapped-type behavior is consistent-ish** | All three keep the resource under a fallback type (`arm_…` / `pulumi_…`) with a warning and "no rules apply" — good parity: nothing is silently dropped at the type level (except Pulumi's empty-type `pulumi_` with no warning, §3.2). |
| 12 | **Detection edge cases** | ARM `Handles` sniffs only the first 64 KiB for the `$schema` marker (miss → falls to manifests); Bicep `.bicepparam` files are unhandled by every adapter (parameter values that could resolve Unknowns are never read). |

### Uncertainty-policy comparison

| Adapter | Unknown representation | Ever guessed? | Ref populated? |
|---------|------------------------|---------------|----------------|
| ARM | `Known:false`, no Ref | No | Never |
| Bicep (via ARM translation) | `Known:false`, no Ref | No | Never |
| Pulumi | `Known:false`; `Ref` = ref body or `fn::*` name | No — except the `True`→`false` bug (§3.5), which is a wrong Known value | Yes, for unresolved `${}` and `fn::*` |
