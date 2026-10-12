# Adapter IR-Mapping Reference — terraform / planjson / cloudformation

Semantic-parity audit baseline. Read-only documentation of how three Aegis
adapters convert source formats into the canonical IR
(`internal/ir/ir.go`: `Resource{Type, Name, Provider, Attributes
map[string]Value, Span}`, `Value{Raw, Known, Span, Ref}`).

Scope: `internal/adapter/terraform/` (`terraform.go`, `hardening.go`),
`internal/adapter/planjson/` (`planjson.go`),
`internal/adapter/cloudformation/` (`cfn.go`, `intrinsics.go`, `props.go`,
`typemap.go`). Sources read 2026-10-12. No code was modified.

Adapter selection (relevant to all three): `cmd/aegis/main.go`
`defaultAdapters()` returns adapters in fixed order and `scanFile`
(`main.go:1020`) picks the **first** adapter whose `Handles(path)` returns
true. Order: `terraform`, `planjson`, `compose`, `pulumi`, `arm`, `bicep`,
`cloudformation`, `manifests`, `dockerfile`. A file with no match is marked
failed with a warning diagnostic ("no adapter handles …; skipped").

**Cross-format parity risks** are flagged with ⚠️ inline and summarized in
§4.

---

## 1. Terraform HCL adapter — `internal/adapter/terraform/`

Files: `terraform.go` (1007 lines; parsing, expression evaluation),
`hardening.go` (188 lines; pre-parse validation).

### 1.1 Entry point & detection

- `Adapter` struct; `New()` constructor; `Name()` returns `"terraform"`.
- `Handles(path)` (`terraform.go:131`): `strings.EqualFold(filepath.Ext(path), ".tf")`
  — case-insensitive `.tf` only. **`.tfvars` is explicitly excluded** (package
  doc: variable definitions are a semantics-layer concern). `.tf.json`
  (Terraform JSON syntax) is likewise *not* claimed — see §1.7.
- `Parse(path, src)` delegates to `ParseModule(path, src)`, returning only
  `Module.Resources`. `ParseModule` additionally exposes `Variables`, `Locals`,
  `ModuleCalls`, `SyntheticResources` (`terraform_variable`,
  `terraform_locals`, `terraform_output`), and `ProviderReqs` for the
  semantics layer (used by `cmd/aegis/main.go:879`).
- Pre-parse hardening runs first: `PreValidate` (`hardening.go:38`).
  - Empty (0-byte) file: valid, zero resources, **not** an error or warning.
  - Hard errors (returned as Go `error`, failing the file): UTF-16 BOM,
    null bytes, size > `discovery.MaxFileBytes` (10 MiB), brace-nesting depth
    > 50 (`MaxNestingDepth`), unbalanced braces (truncation heuristic).
  - The brace scan is best-effort (skips strings, heredocs, `#`/`//`/`/* */`
    comments); the comments admit false positives on exotic-but-valid HCL.
- `lenientParseConfig` (`terraform.go:209`): strict `hclsyntax.ParseConfig`;
  on "Missing attribute separator" errors (common in generator-written
  single-line object constructors without commas), commas are inserted at the
  exact diagnostic byte offsets and the source is re-parsed, iterating up to
  32 passes. Falls back to the original strict result if recovery fails.
  Purely additive: cleanly-parsing files are untouched.

### 1.2 Type mapping

- **Identity mapping — no typemap table.** `Type` is the resource block's
  first label verbatim (`resourceFromBlock`, `terraform.go:575`):
  `resource "aws_s3_bucket" "data"` → `Type: "aws_s3_bucket"`.
- `Provider` via `providerOf` (`terraform.go:655`): leading namespace before
  the first `_` (`aws_s3_bucket` → `aws`). A type with no underscore maps to
  itself.
- Fallback for "unmapped" types: none needed — every well-formed resource
  block is emitted; rules simply don't match unknown types.
- Synthetic resource types injected into `mod.Resources` (visible to rules):
  - `data` blocks → `Type: "terraform_data"`, `Name: "<type>.<name>"`
    (e.g. `aws_ami.ubuntu`), `Provider: "terraform"` — **not** skipped, despite
    the package doc comment ("`data` blocks … are skipped without error")
    which is **stale**; the code emits them.
  - `terraform { }` block → `terraform_config` (`terraformConfigResource`),
    with `required_version`, `backend_type`, and a sorted `required_providers`
    block list of `{name, source, version}` maps (version absent when the
    entry has none, Unknown when non-static).
  - `backend "TYPE" { }` nested blocks → `terraform_backend` named after the
    backend type (e.g. `s3`), attributes from the backend body.
  - `provider "NAME" { }` blocks → `terraform_provider` with the provider body
    as attributes.
- `terraform_variable` / `terraform_locals` / `terraform_output` synthetic
  resources are kept in `Module.SyntheticResources`, **separate** from
  `Resources` (so the semantics layer's infrastructure-resource counting is
  unaffected); they are only visible via `ParseModule`, not via `Parse`.

### 1.3 Attribute mapping

- Attribute names are verbatim HCL (already snake_case in Terraform); no name
  conversion.
- `attributesFromBody` (`terraform.go:613`): plain attributes first, then
  nested blocks. Each nested block type becomes `[]ir.Value` of
  `map[string]ir.Value`; repeated blocks append. On an attribute/block-type
  name collision, **the block list wins** (deterministic).
- `dynamic` blocks are **not expanded**: kept verbatim under the `"dynamic"`
  key with the target block label preserved in `"__label"`. The semantics
  layer expands them later and warns for blocks it cannot expand (no adapter
  diagnostic here, by design).
- `count` / `for_each` remain ordinary attributes in `Attributes`; when their
  expression is unresolvable a **warning** diagnostic is emitted ("analyzed
  as a single instance") instead of silently analyzing one instance.

### 1.4 Expression / intrinsic resolution (`valueFromExpr`, `terraform.go:668`)

Static whitelist (`staticExpr`, `terraform.go:790`) — only these become
`Known: true`:
- `LiteralValueExpr` (strings, numbers, bools), single-part `TemplateExpr`
  (plain strings, heredocs), `TupleConsExpr`/`ObjectConsExpr` composed of
  statics (bare-identifier object keys count as literal strings via
  `staticObjectKey`), unary minus on a numeric literal (`-5`).

Everything else degrades as follows:
- **`jsonencode()` special case** (only whitelisted function): one argument,
  fully static → Known JSON string (`jsonEncodeStatic`); argument with
  static-or-ref parts → Unknown container preserving refs with
  `EncodeJSON: true` so the semantics layer can JSON-encode after resolution.
- **Bare traversals** (`var.x`, `local.tags`, `data.aws_ami.ubuntu.id`,
  `each.key`) → `Known: false` with `Ref` set to the dotted path
  (`traversalRef`, `terraform.go:752`); static string/number index steps render
  as `["k"]` / `[n]`; non-static index steps → plain Unknown, **ref lost**.
- **Tuples/objects of static-or-ref elements** (`refOrPartial`) → Unknown
  **container** (`Known: false`) with refs preserved inside for the semantics
  layer.
- ⚠️ **Plain Unknown, ref dropped**: multi-part template strings
  (`"prefix-${var.x}"`), conditionals, binary operators, splat expressions,
  function calls other than `jsonencode`, and anything unrecognized. The
  reference information is **silently discarded** (no diagnostic, no Ref).
- `ctyToValue` (`terraform.go:920`): null / unknown / exotic cty types →
  Unknown; **a container with ANY unknown child degrades the whole container
  to Unknown** (all-or-nothing; refs inside are lost on this path).
- A `recover()` guard converts any evaluation panic into Unknown — parsing
  never crashes the scanner.

### 1.5 Uncertainty policy

- `Known: false` is explicit and never guessed: "Rules must treat unknown
  values as 'cannot decide', not as false" (ir.go). Refs are preserved only
  where syntactically extractable (bare traversals, static-or-ref
  composites); nothing is inferred.

### 1.6 Diagnostics

- HCL syntax diagnostics → `ir.Diagnostic` with level `error`/`warning` and
  source spans; hard Go `error` only when the file cannot be parsed as HCL at
  all (or `PreValidate` fails).
- Warnings: resource block with ≠2 labels (skipped); `module`/`provider`
  block with ≠1 label (skipped); `count`/`for_each` with unresolvable
  expression (analyzed as single instance).
- ⚠️ **Silently skipped (no diagnostic):**
  - `data` block with ≠2 labels (`continue` with no diagnostic).
  - `variable` / `output` block with ≠1 label.
  - `backend` nested block with ≠1 label.
  - Block types with no case in the `ParseModule` switch: `moved`, `import`,
    `removed`, `check`, `ephemeral` (and any future block type) — silently
    ignored. Note: `moved` blocks carry refactoring semantics invisible to
    the scanner.
  - Inside `terraform { }`: nested blocks other than `backend` /
    `required_providers` (e.g. `cloud`, `experiments`) silently ignored.
  - Non-native HCL body (JSON syntax) → warning "block enumeration skipped",
    but unreachable via `Handles` (see §1.7).

### 1.7 Known gaps

- No typemap: cross-provider type normalization is the rules' problem; the
  adapter assumes TF-canonical types.
- **Terraform JSON syntax (`.tf.json`) is not claimed** by `Handles` (ext
  check is `.tf` only); such files fall through to the `manifests` adapter.
- Variables, locals, module inputs, and data sources are **not resolved** at
  the adapter level — resolution is the semantics layer's job (Milestone 2+);
  adapter output is intentionally reference-preserving but unresolved.
- `dynamic` blocks unexpanded; `for_each` over unresolvable expressions
  analyzed as a single instance (with warning).
- Package-doc comment claiming data blocks are "skipped without error" is
  stale (they are now emitted as `terraform_data`).

---

## 2. Terraform plan JSON adapter — `internal/adapter/planjson/`

File: `planjson.go` (199 lines). Read-only analysis of
`terraform show -json plan.tfplan` output.

### 2.1 Entry point & detection

- `Name()` returns `"terraform-plan"` (note: not `"planjson"`).
- `Handles(path)` (`planjson.go:35`): `strings.HasSuffix(strings.ToLower(path),
  ".plan.json")` — **narrow on purpose** to avoid colliding with the
  manifests/arm adapters on generic `.json`. The cloudformation adapter
  explicitly excludes this suffix.
- `Parse`: `json.Unmarshal` into a minimal schema (`planFile` →
  `planned_values.root_module`); `DisallowUnknownFields` intentionally off
  (schema is version-dependent). Recursively walks `root_module` and
  `child_modules`. Only `planned_values` is read — `resource_changes`,
  `configuration`, and other sections are **ignored**.

### 2.2 Type mapping

- **Identity mapping — no typemap table.** `Type` is the plan's resource type
  verbatim (e.g. `aws_subnet`).
- `Provider` via `providerOf` (`planjson.go:169`): same leading-namespace rule
  as the terraform adapter (`aws_subnet` → `aws`).
- `Name` is module-qualified (`qualifiedName`, `planjson.go:146`): root-module
  resources keep the plan's short name (e.g. `data`); child-module resources
  become `<module path>.<name>` (e.g. `module.vpc.a`), parsed from the
  authoritative plan address. Consequently `Address()` is unique across
  modules; for root resources it equals the plan address exactly.
  Malformed addresses fall back to the short name, then the full address —
  the resource is never dropped for addressing reasons.
- ⚠️ **Data-source parity mismatch**: a plan data source with address
  `data.aws_ami.ubuntu` becomes `Type: "aws_ami"`, `Name: "data.ubuntu"`.
  The terraform adapter instead emits data blocks as `Type:
  "terraform_data"`, `Name: "aws_ami.ubuntu"`. Same logical object, different
  IR identity across formats.

### 2.3 Attribute mapping

- `values` map → `Attributes` 1:1 (`convertResource`, `planjson.go:125`); keys
  are verbatim (plan JSON already uses TF snake_case). **No structural
  special-casing** — nested blocks appear as generic lists/maps of values.
- `SensitiveValues` is walked in parallel: a sensitivity marker of `true` at
  a position redacts the **entire subtree** to `UnknownValue` — plaintext
  secrets never enter the IR, at the cost of losing structure below the
  marker. Per-element sensitivity is honored inside lists and maps.
- No spans exist in plan JSON: **every `Span` is the file itself
  (`1:1–1:1`)** via `fileSpan`. Evidence for findings points at the whole
  file.

### 2.4 Expression / intrinsic resolution

- None — plan JSON values are already evaluated. `toValue`
  (`planjson.go:165`): JSON `null` (unknown at apply time) → Unknown;
  sensitivity `true` → Unknown; Go types `bool`/`string`/`float64`
  → Known; `[]any`/`map[string]any` recurse (Known containers);
  anything `encoding/json` cannot produce → defensive Unknown (never panics).
- No `Ref` values are ever produced; everything is resolved-or-unknown.

### 2.5 Uncertainty policy

- Unknown iff: JSON null, sensitivity-marked, or undecodable shape. Never
  guessed. Note the asymmetry with source adapters: values the provider
  computed during plan (e.g. `tags_all`) may be Known here while Unknown in
  HCL source, so rule coverage legitimately differs between the two formats.

### 2.6 Diagnostics

- JSON decode failure → **hard error** (`planjson: cannot decode …`).
- Missing `planned_values` → **warning** ("plan JSON has no
  planned_values; nothing to scan"), zero resources, no error.
- Resource record missing `type` or `address` → **warning** ("skipping
  resource with missing type or address"), skipped.
- A non-plan JSON file named `*.plan.json` parses "successfully" into the
  no-`planned_values` warning — content is not validated beyond the schema
  subset.

### 2.7 Known gaps

- No source positions (all spans 1:1) — findings lose precise evidence
  location vs. the HCL adapter.
- `resource_changes` ignored: create/update/no-op/delete intent is not
  represented; a planned-destroy resource still appears as a normal resource.
- `configuration` section ignored: expressions, `depends_on`, and
  unevaluated structure are invisible.
- Sensitive subtrees are wholesale redacted (by design), so secret-adjacent
  rules cannot inspect structure below a sensitive marker.
- Data sources get a different IR identity than in the terraform adapter
  (§2.2 ⚠️).

---

## 3. CloudFormation adapter — `internal/adapter/cloudformation/`

Files: `cfn.go` (407 lines; detection, template orchestration, YAML helpers),
`intrinsics.go` (377 lines; `Ref`/`Fn::*` resolution, `snakeCase`),
`props.go` (487 lines; 15 special converters), `typemap.go` (152 lines;
`cfnToTF` map).

Strategy (per package doc): convert CFN resources into the canonical IR
**using Terraform-style resource types and snake_case attribute names** so
the existing AWS rule pack applies without new rules.

### 3.1 Entry point & detection

- `Adapter` struct; `New()`; `Name()` returns `"cloudformation"`.
- `Handles(path)` (`cfn.go:55`): explicit exclusion of the `.plan.json`
  suffix, then an **extension gate** (`.yaml`, `.yml`, `.json`, `.template`),
  then **content sniffing** (`looksLikeCFN`, `cfn.go:67`) because the
  manifests adapter claims every `.yaml`/`.yml`/`.json` file:
  1. Fast path: byte scan for `AWSTemplateFormatVersion`.
  2. Structural: YAML-parse and require a top-level mapping with `Resources:`
     containing at least one entry whose `Type:` scalar starts with `AWS::`.
- ⚠️ `looksLikeCFN` **re-reads the file from disk** (`readBounded`, capped at
  1 MiB + 1 byte) instead of using the `src` bytes `Parse` will receive — a
  minor TOCTOU/double-read quirk in the scan flow.
- Registration order dependency (documented in `cfn.go` and
  `cmd/aegis/main.go`): `cloudformation.New()` is registered **before**
  `manifests.Adapter{}`; first-match wins. A YAML file with `Resources:` but
  no `AWS::*` type (e.g. a SAM-less custom template, or a Kubernetes-adjacent
  file) falls through to manifests.
- `Parse`: `yaml.Unmarshal` into `yaml.Node` (JSON is a YAML subset, so one
  parser handles both). Invalid YAML/JSON → **error diagnostic**, nil
  resources, **nil Go error** (does not hard-fail the scan). Top-level not a
  mapping → warning, skipped. Sections parsed: `Parameters`, `Resources`,
  `Outputs`; a `Mappings` section triggers a by-design warning
  ("Mappings are not resolved; Fn::FindInMap values will be unknown").
  Resources convert in document order (deterministic); synthesized companions
  appended after; `Outputs` become synthetic `cfn_output` resources
  (secret-detection parity with `terraform_output`).

### 3.2 Type mapping

- `typemap.go`: `cfnToTF` map, **`cfnTypeToTF`** lookup. **105 entries**
  (counted), AWS-only, spanning S3, EC2/VPC, IAM, RDS/DynamoDB/ElastiCache/
  Redshift/Neptune/DocDB, Lambda/SAM (`AWS::Serverless::Function` →
  `aws_lambda_function`, `AWS::Serverless::Api` →
  `aws_api_gateway_rest_api`), ECS/EKS, ELB/ALB, Route53/CloudFront/APIGW,
  KMS/SecretsManager/SSM/WAF/Shield/GuardDuty/SecurityHub/Macie/Config,
  CloudTrail/CloudWatch/Logs, SNS/SQS, EFS/Backup, ACM, OpenSearch/
  Elasticsearch/Kinesis/MSK/Athena/Glue/EMR, SageMaker/Bedrock, Events/
  StepFunctions/AppSync, ECR, AutoScaling. Notably lossy conflations:
  `AWS::EC2::SecurityGroupIngress` **and** `AWS::EC2::SecurityGroupEgress`
  both → `aws_security_group_rule`; `AWS::IAM::ManagedPolicy` →
  `aws_iam_policy`.
- ⚠️ **Fallback for unmapped types: the resource is dropped.** `convertResource`
  (`cfn.go:200`) emits a **warning** ("unmapped resource type …; skipped")
  and returns `ok=false` — the resource never reaches the IR. Any CFN type
  outside the 105 (third-party, `Custom::`, newer AWS types) is invisible to
  rules. The terraform/planjson adapters never drop resources for type
  reasons — this is the largest structural parity gap of the three.
- Resource with no `Type` scalar → warning + skipped.
- `Name` is the CFN **logical ID verbatim** (typically PascalCase, e.g.
  `MyBucket`) — not normalized, so `Address()` (`aws_s3_bucket.MyBucket`)
  differs in naming convention from TF sources by design.
- `Provider` is hardcoded `"aws"` for converted resources (not inferred);
  synthetic `cfn_output` resources use `Provider: "cfn"`.

### 3.3 Attribute mapping

- Generic path (`convertProperties`, `props.go:46`): every `Properties:`
  entry is converted; keys pass through `snakeCase` (`intrinsics.go:351`);
  values through `resolveValue`. Recursion is generic for nested maps/lists.
- ⚠️ **`snakeCase` is naive**: it inserts `_` before *every* uppercase letter
  after position 0. Consecutive capitals produce non-TF names:
  `KMSMasterKeyID` → `k_m_s_master_key_id` (TF: `kms_master_key_id`),
  `DBInstanceIdentifier` → `d_b_instance_identifier` (TF: `identifier`),
  `SSEAlgorithm` → `s_s_e_algorithm` (TF: `sse_algorithm`). Any property
  containing an acronym that is **not** covered by a special converter gets a
  mangled attribute name that TF-keyed rules will never match. (Names like
  `VpcId` → `vpc_id` and `KmsKeyId` → `kms_key_id` happen to come out right;
  the failure mode is specifically runs of capitals.)
- **15 special converters** (`specialConverters`, `props.go:25`) reshape
  high-value types into the TF shapes rules expect; each may also emit
  **companion resources** buffered on the template and appended after the
  main pass:
  - `AWS::S3::Bucket` (`convertS3Bucket`): `BucketEncryption` →
    `server_side_encryption_configuration` (TF shape:
    `[{rule: [{apply_server_side_encryption_by_default: [{…}]}]}]`);
    `VersioningConfiguration{Status}` → `versioning: [{enabled: bool}]`;
    `LoggingConfiguration` → `logging: [{target_bucket, target_prefix}]`;
    `WebsiteConfiguration` → `website: [{index_document, error_document}]`;
    `PublicAccessBlockConfiguration` → companion
    `aws_s3_bucket_public_access_block` named `<logicalID>-pab` with
    `bucket: <logicalID>` (⚠️ the *logical ID*, not the bucket name) plus the
    four `block_*` flags; the inline key is deleted from the bucket.
  - `AWS::S3::BucketPolicy`: `PolicyDocument` → `policy` as a JSON-encoded
    string (`jsonString`); `Bucket` → `bucket`.
  - `AWS::IAM::Role`: `AssumeRolePolicyDocument` → `assume_role_policy`
    (JSON string); each inline `Policies[]` entry → companion
    `aws_iam_role_policy` (`name`, `role: <logicalID>`, `policy` JSON
    string); unresolvable policy names fall back to `<logicalID>-inline`.
  - `AWS::IAM::Policy` / `ManagedPolicy`: `PolicyDocument` → `policy`;
    `PolicyName` → `name`; `Roles`/`Users`/`Groups` carried over snake_cased.
  - `AWS::IAM::User`: inline `Policies[]` → companion `aws_iam_user_policy`.
  - `AWS::KMS::Key`: `KeyPolicy` → `policy` (JSON string);
    `EnableKeyRotation` passed through.
  - `AWS::EC2::SecurityGroup`: `GroupDescription` → `description`;
    `SecurityGroupIngress/Egress` → `ingress`/`egress` TF block lists
    (`sgRules`: `IpProtocol`→`protocol`, `FromPort`→`from_port`,
    `ToPort`→`to_port`, `CidrIp` wrapped as `cidr_blocks: […]`,
    `CidrIpv6`→`ipv6_cidr_blocks`, SG id fields renamed); `VpcId` →
    `vpc_id`.
  - `AWS::CloudTrail::Trail`: explicit renames (`IsLogging`→`enable_logging`,
    `KMSKeyId`→`kms_key_id`, `CloudWatchLogsRoleArn`→
    `cloud_watch_logs_role_arn`, …), deleting the naive snake_case key when
    it differs.
  - `AWS::DynamoDB::Table`: `SSESpecification` →
    `server_side_encryption: [{enabled, kms_key_arn}]`.
  - `AWS::ElastiCache::ReplicationGroup`: `AtRestEncryptionEnabled` /
    `TransitEncryptionEnabled` passed through.
  - `AWS::OpenSearchService::Domain` / `AWS::Elasticsearch::Domain`:
    `EncryptionAtRestOptions` → `encrypt_at_rest: [{enabled, kms_key_id}]`;
    `NodeToNodeEncryptionOptions` → `node_to_node_encryption: [{enabled}]`.
  - `AWS::RDS::DBInstance`, `AWS::Redshift::Cluster`: **no-op converters**,
    explicitly documented as clarity guards — generic snake_case conversion
    applies (including its acronym-mangling risk, §3.3 ⚠️).
- Block lists are built as single-element `[]ir.Value{map}` via `blockList`
  (`props.go:172`), matching TF block shape.
- Spans: a property's value span is overwritten to point at the **property
  key node** when the value is Known; nested-node `EndCol` is approximated as
  `Column + len(Value)` (`nodeSpan`, `cfn.go:277`) — imprecise for
  multi-line nodes.

### 3.4 Expression / intrinsic resolution (`intrinsics.go`)

`resolveValue` handles both YAML tag shorthand (`!Ref`, `!Join`, `!Sub`,
`!GetAtt`, `!If`, `!ImportValue`, `!FindInMap`, `!Select`, `!Split`,
`!GetAZs`, `!Base64` via `resolveTag`) and single-key mappings
(`{Ref: …}`, `{Fn::X: …}` via `resolveIntrinsic`). Unrecognized tag →
falls through to normal node handling.

**Resolved statically (Known):**
- `Ref` to a parameter **with a `Default`** → the default value.
- `Fn::Join` with static delimiter and **all** parts statically resolvable to
  strings → joined string.
- `Fn::Sub` → string when the template and every `${…}` is resolvable;
  supports the `[template, {var: value}]` form and `${!Literal}` escapes;
  dotted `${LogicalId.Attr}` against a known resource → unresolvable.
- `Fn::Base64` → the **inner value returned as-is** (base64 is treated as a
  transport detail and not applied).
- Policy-document helpers (`jsonString`): fully-resolved maps JSON-encoded
  to Known strings (used for IAM/S3/KMS `policy` attributes).

**Unknown-with-Ref (never guessed):**
- `Ref` to parameter without default → `cfn.parameter.<name>` (the paramDef
  itself carries `Ref: "cfn.parameter.<name>"` when no default).
- Pseudo-parameters (`AWS::Region`, `AWS::AccountId`, …) →
  `cfn.pseudo.<name>`.
- `Ref` to a resource logical ID → `cfn.resource.<name>` (ref to the
  resource itself, not dereferenced).
- `Ref` to anything else → `cfn.ref.<name>`.
- `Fn::GetAtt` (both `[id, attr]` and `"id.attr"` forms) → **always**
  `cfn.getatt.<id>.<attr>` — ⚠️ never dereferenced, even for resources
  already converted in the same template (the `t.converted` map exists but
  `GetAtt` does not consult it).
- `Fn::If`, `Fn::ImportValue`, `Fn::FindInMap`, `Fn::Select`, `Fn::Split`,
  `Fn::GetAZs`, `Fn::Transform`, `Fn::ToJsonString` → `cfn.intrinsic.<Key>`.
- Any other single-key mapping that *looks* like an intrinsic (`Ref` or
  `Fn::` prefix) but isn't handled → `cfn.intrinsic.<Key>`.
- Malformed intrinsic shapes → `cfn.join`, `cfn.sub`, `cfn.ref`,
  `cfn.getatt`, `cfn.base64` refs (no diagnostic; the Ref records it).
- `Fn::Sub` with any unresolvable `${…}` (unbalanced braces, unknown var,
  dotted resource attr, pseudo-param) → whole value `cfn.sub`.
- `jsonString` over an unresolvable document → `cfn.jsonencode` ref.

**Silently dropped / lossy (flagged):**
- ⚠️ `Fn::Join` / `Fn::Sub` are **all-or-nothing**: one unresolvable part
  discards the resolvable parts (no partial value, no per-part refs).
- ⚠️ `Mappings:` values are never read (warning emitted once per template);
  `Conditions:` are not modeled at all — `Fn::If` branches are opaque.
- `DeletionPolicy`, `DependsOn`, `Metadata`, `CreationPolicy`,
  `UpdatePolicy` flow through generic conversion as ordinary attributes
  (`deletion_policy`, …) with no semantic interpretation.
- YAML merge keys (`<<:`) are not expanded — they surface as a literal
  `<<` attribute (merge semantics lost). YAML anchors/aliases otherwise
  resolve via `AliasNode`.

### 3.5 Uncertainty policy

- Nothing is guessed; unresolvable values carry `Ref` in the `cfn.*`
  namespace (`cfn.parameter.*`, `cfn.pseudo.*`, `cfn.resource.*`,
  `cfn.getatt.*`, `cfn.intrinsic.*`, `cfn.join`, `cfn.sub`, `cfn.jsonencode`).
- ⚠️ **Two deviations from the IR contract** ("Known == false means the
  value could not be resolved statically", ir.go):
  1. `scalarValue` (`cfn.go:296`) maps YAML `!!null` → `Value{Raw: nil,
     Known: true}` — null is marked **Known**, while the terraform adapter
     (cty null → Unknown) and planjson (JSON null → Unknown) both mark null
     unknown.
  2. `resolveValue` marks `SequenceNode` and generic `MappingNode` containers
     `Known: true` **unconditionally**, even when children are Unknown —
     the terraform adapter instead degrades any container with an unknown
     child to Unknown. Rules trusting container-level `Known` will
     over-trust CFN values (e.g. an SG `ingress` list containing one
     unresolvable rule still reports `Known: true` at the list level).

### 3.6 Diagnostics

- Invalid YAML/JSON → **error** diagnostic, nil resources, nil Go error
  (scan continues).
- Top-level document not a mapping → **warning**, skipped.
- `Mappings:` present → **warning** (by design, documents FindInMap
  blindness).
- Resource missing `Type` → **warning** + skipped.
- **Unmapped CFN type → warning + resource skipped entirely** (§3.2 ⚠️).
- Malformed intrinsics degrade to unknown Refs **without diagnostics**
  (silent by design, Ref records the cause).

### 3.7 Known gaps

- Only **105 AWS types** mapped; `Custom::`, third-party, and newer AWS
  types are dropped with a warning — whole-resource blindness.
- `Conditions`, `Mappings`, cross-stack `ImportValue`, and `Fn::GetAtt`
  dereferencing are unimplemented (unknown by design).
- Parameters resolve only via `Default`; runtime-supplied parameter values
  are invisible.
- Naive `snakeCase` mangles acronym-bearing property names outside special
  converters (§3.3 ⚠️); `AWS::RDS::DBInstance` and `AWS::Redshift::Cluster`
  converters are explicit no-ops relying on generic conversion.
- `Fn::Base64` is a pass-through (no encoding applied) — rules inspecting
  `user_data`-style attributes see the raw string, unlike the deployed
  base64 form.
- Companion resources reference parents by **logical ID**, not physical
  name/ARN (e.g. S3 PAB `bucket: <logicalID>`).
- `Handles` re-reads the file from disk for sniffing (§3.1 ⚠️).

---

## 4. Cross-format parity risk summary

Ordered by severity for the audit:

1. **Whole-resource drops (cloudformation only).** Unmapped CFN types are
   skipped with a warning; terraform/planjson never drop resources for type
   reasons. A template using a type outside the 105-entry map is partially
   invisible. (§3.2)
2. **Container `Known` semantics differ.** CFN marks lists/maps `Known:
   true` even with unknown children; terraform degrades such containers to
   Unknown; planjson marks nulls unknown. Rules that gate on container-level
   `Known` behave differently per format. (§3.5)
3. **Null handling differs.** CFN `!!null` → `Known: true, Raw: nil`;
   terraform cty null → Unknown; plan JSON null → Unknown. (§3.5)
4. **Naive `snakeCase` mangles acronyms** (`KMSMasterKeyID` →
   `k_m_s_master_key_id`) for CFN properties outside the 15 special
   converters; TF-keyed rules never see these attributes. (§3.3)
5. **Data-source identity mismatch.** Terraform adapter: `Type:
   "terraform_data"`, `Name: "aws_ami.ubuntu"`. Planjson: `Type: "aws_ami"`,
   `Name: "data.ubuntu"`. Cross-format joins on data sources break.
   (§1.2, §2.2)
6. **Reference loss in terraform adapter.** Interpolated strings,
   conditionals, binary ops, and non-`jsonencode` function calls become
   plain Unknown with **no Ref** — the dependency edge is silently dropped,
   unlike bare traversals which preserve it. (§1.4)
7. **`Fn::GetAtt` never dereferences** in the CFN adapter, even for
   same-template resources; terraform's traversal refs at least preserve the
   path for the semantics layer. (§3.4)
8. **Span fidelity.** Terraform: precise block spans. CFN: node spans with
   approximated end columns; known property values re-pointed at the key
   node. Planjson: every span is the whole file (`1:1–1:1`). Evidence
   quality degrades across the three.
9. **Silent skips (terraform).** `moved`/`import`/`removed`/`check`/
   `ephemeral` blocks, mislabeled `data`/`variable`/`output`/`backend`
   blocks, and non-`backend`/`required_providers` children of `terraform { }`
   are ignored with no diagnostic. (§1.6)
10. **Plan-only blind spots.** `resource_changes` (create/delete intent) and
    `configuration` (expressions, `depends_on`) are ignored; sensitive
    subtrees are wholesale redacted. (§2.7)
11. **CFN companion naming.** Synthesized companions (`<logicalID>-pab`,
    inline IAM policies) and logical-ID-based parent refs have no direct
    counterpart in TF sources, where these are separate resources or inline
    blocks — cross-format resource-graph matching must account for this.
    (§3.3)
12. **`.tf.json` gap.** Terraform JSON syntax files are not claimed by the
    terraform adapter and fall through to `manifests`. (§1.7)
13. **Detection fragility.** CFN detection depends on content sniffing with a
    disk re-read, ordered before `manifests`; a CFN template without
    `AWSTemplateFormatVersion` and without an `AWS::*`-typed resource (e.g.
    parameters-only or custom-type-only templates) is misclassified.
    (§3.1)
