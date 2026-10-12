# Adapter IR Mapping — Dockerfile, Compose, Manifests

Baseline for the semantic-parity audit. Read-only analysis of the three
adapters as they exist in `~/workspace/aegis-engine/` (module `aegis`).
Code citations are to `internal/adapter/<name>/<file>.go` unless noted;
IR types are in `internal/ir/ir.go`.

Source for each section: the adapter's own package doc comment (which is
accurate and doubles as the contract), the source, and the sibling
`*_test.go` files.

---

## 1. Dockerfile adapter (`internal/adapter/dockerfile/`)

Adapter name: `"dockerfile"` (`Adapter.Name()`). Source: `dockerfile.go`
(777 lines). Tests: `dockerfile_test.go`.

### 1.1 Entry point & detection

- `Adapter.Handles(path)` (`dockerfile.go`, `Handles`): matches the file
  **basename** only (via `filepath.Base`). True when:
  - basename equals `Dockerfile` case-insensitively (`strings.EqualFold`);
  - or the lower-cased basename starts with `dockerfile.` (e.g.
    `Dockerfile.prod`, `dir/Dockerfile.dev`);
  - or the lower-cased basename ends with `.dockerfile` (e.g.
    `app.dockerfile`).
  - Verified negatives in `dockerfile_test.go` (`TestHandles`):
    `Dockerfilex`, `myDockerfile` are **rejected**; `main.tf`,
    `docker-compose.yml` are rejected.
  - Note: it runs **last** in the CLI's adapter list
    (`cmd/aegis/main.go`, `defaultAdapters`), so no precedence conflict.
- `Adapter.Parse(path, src)` never returns a hard error for Dockerfile
  content — "Malformed input yields best-effort resources plus a
  diagnostic, never a panic or an error" (package doc). `tokenize()`
  handles everything; the only diagnostics it can emit is the warning
  `"no Dockerfile instructions found"`.

### 1.2 High-level parse flow

1. `tokenize(src)`: normalizes `\r\n`, joins backslash continuations
   (the start *line* is the first physical line; continuation args are
   space-joined), strips `#` comments **quote-aware**
   (`stripComment` respects `"`/`'`), drops blank lines, upper-cases the
   first field as the instruction name. Everything is line/column 1-based;
   every emitted `ir.Span` is degenerate: `StartCol: 1, EndCol: 1`,
   `EndLine == StartLine`.
2. `Parse` walks the instruction list with a per-stage accumulator
   (`stage` struct). Each `FROM` flushes the previous stage into an
   `ir.Resource` and opens a new one. After the loop the final stage is
   flushed on the last instruction's line; every stage then receives
   `total_stages` (the file-wide stage count).
3. `Ref` is never set; `Known` is always `true` on everything this adapter
   emits (see §1.5).

### 1.3 Type mapping

- Exactly one IR type: **`docker_stage`**, Provider `"docker"`.
- One resource per `FROM` build stage. `Resource.Name` = the `AS <alias>`
  (from `parseFrom`, which skips leading `--flag` args so
  `FROM --platform=linux/amd64 ... AS b` works); when unnamed,
  `stage<N>` with N = 0-based stage index.
- Resource `Span`: `FROM` line through the line of the last instruction
  before the next `FROM` (or EOF). Attribute spans are mostly the
  instruction line; aggregate lists reuse the whole stage span.

### 1.4 Attribute mapping

Per-stage attributes (attribute → source), all `Known: true`:

| Attribute | Source / rule |
|---|---|
| `base_image` | Full image ref from `FROM` (`parseFrom`), e.g. `"ubuntu:22.04"` |
| `base_tag` | Tag after the last `:` past the last `/` (`imageTag`); digest (`@sha256:…`) stripped; `""` when absent |
| `user` | **Last** `USER` directive only; group suffix stripped (`root:group` → `root`). Absent when no `USER`. Note: `USER 0` is stored as `"0"` — **not** normalized to `root` (see test `TestParseUserRootVariants`) |
| `exposed_ports` | `[]Value` of `EXPOSE` fields with `/proto` suffix stripped (`8080/tcp` → `"8080"`) |
| `env_names` | `[]Value` of ENV variable *names* (values never stored) |
| `env_secrets` | `[]Value` of `{name, span}` maps for secret-looking names with **literal** values. **Values are redacted — never stored** |
| `arg_names` / `arg_secrets` | Same pattern for `ARG`; `arg_secrets` uses `secretMap(name, span)` (`{name, span}`); default values redacted |
| `workdir` | Last `WORKDIR`, quotes stripped; absent when none |
| `shell` | Raw `SHELL` args string; absent when none |
| `labels` | `[]Value` of LABEL **keys only** (values discarded, `parseLabel`) |
| `has_stopsignal`, `uses_onbuild`, `uses_volume`, `uses_maintainer` | bools |
| `maintainer_span` | present (= true) only when `MAINTAINER` used, for evidence span |
| `copy_sources` | `[]Value` of COPY **source** paths; **destination dropped**; JSON-array form supported; flags (`--chown`, `--from`) parsed out |
| `copy_chown_used` | bool — any COPY with `--chown` |
| `cmd_shell_form` / `entrypoint_shell_form` | `!isExecForm(args)` — exec form detected only by a leading `[` |
| `has_healthcheck` | bool; `HEALTHCHECK NONE` sets it **false** |
| `uses_add` / `add_span` / `add_remote` | `uses_add` bool; `add_span` evidence bool; `add_remote` bool when any non-dest source is `http(s)://` |
| `run_commands` | `[]Value` of raw RUN bodies (continuations joined) |
| `sudo_used` | bool — `usesSudo` tokenizes on whitespace, strips `;&|()` and matches a token exactly equal to `sudo` |
| `total_stages` | int, file-wide stage count on every stage |

Instruction specifics:

- **FROM**: `parseFrom` drops `--flag`/`--flag=value` leading flags.
  `base_tag` = `""` when the reference carries no explicit tag
  (implicit `:latest` is **not** materialized).
- **ARG**: `parseArg` splits `name=default`; **the default is stored in
  the internal `argKV.def` but never exported into IR attributes** — only
  the name appears (`arg_names`); `def` is used only for the secret-literal
  check. ARGs appearing **before the first FROM** are "global": they are
  seeded onto the **first stage only** (`seedGlobalArgs` at
  `stageCount == 1`), then `globalArgs = nil`.
- **ENV**: both `KEY=val` and `KEY val` forms (`parseEnv`); quote-aware
  field splitting (`splitEnvFields`). A value counts as *literal*
  (`isLiteralValue`) when non-empty, quotes-stripped, and containing no
  `$`. Secrets: name matches one of
  `PASSWORD PASSWD SECRET TOKEN API_KEY APIKEY PRIVATE_KEY PRIVATEKEY
  CREDENTIAL AUTH` (substring, case-insensitive) AND literal non-empty
  value → `env_secrets` gets `{name, span}`; the value itself is redacted.
- **COPY**: non-flag fields, all but last = sources (`parseCopy`);
  `--chown` detected in both `--chown=…` and `--chown …` forms;
  `--from=builder` flags are silently dropped (cross-stage copies are not
  modeled).
- **USER**: only the first whitespace field; `user:group` → `user`.
- **HEALTHCHECK**: any args not starting with `NONE` (case-insensitive)
  → `has_healthcheck = true`. The check command itself is not retained.
- **CMD/ENTRYPOINT**: shell-form flag set from leading `[` test only;
  empty args (`CMD` alone) leave the default `false`.

### 1.5 Resolution

- **No variable substitution anywhere.** `${VAR}` / `$VAR` are never
  expanded: `FROM $IMAGE:$TAG` would land in `base_image` verbatim as
  `"$IMAGE:$TAG"`. There is no build-arg table carried between stages
  (only global args → names on stage 0). Rules must expect `$` in
  `base_image`, `run_commands`, `user`, `workdir`.
- Nothing is marked `Unknown`: this adapter emits **zero** `Known: false`
  values and **zero** `Ref`s. Everything it reports is "known", even when
  the source is inherently unresolvable (e.g. `USER $APP_USER` is known
  `"$APP_USER"`).

### 1.6 Uncertainty policy

- `Known` is uniformly `true`. Uncertainty is expressed *structurally*,
  not via `Known: false`:
  - attribute absent (`user` when no USER),
  - empty list (`exposed_ports` etc. — always present as known-empty),
  - value redaction (secret values never enter the IR),
  - boolean defaults `false` (`has_healthcheck`, `sudo_used`, …).
- **Semantic-loss risk (HIGH):** an unresolved value (`$FOO`) is
  represented as a known string containing `$FOO`. Per the IR contract
  (`ir.go`), rules should treat `Known == false` as "cannot decide";
  here rules get a *known* value that is actually symbolic. Any rule doing
  string matching on `base_image`/`user`/`workdir` can silently
  misclassify, e.g. a "base image pinned to digest/tag" rule would treat
  `FROM $BASE_IMAGE` as a known untagged-but-present image.
  The single exception is secret detection: values containing `$` are
  deliberately treated as *non-literal* (`isLiteralValue`) so `$DB_PASS`
  is not flagged as a hardcoded secret — that behavior is correct.

### 1.7 Diagnostics

- **Warning** `"no Dockerfile instructions found"` — emitted only when
  the tokenizer yields zero instructions from non-blank input. Blank
  input is silent.
- **No errors possible** from Dockerfile content (`Parse` returns `nil`
  error in all paths tested; `TestParseMalformedNoCrash` covers empty
  input, dangling continuations, unclosed quotes, `FROM` with no args).
- **Silently skipped constructs (no diagnostic):**
  - Any instruction not in the handled set (the `switch` has no
    `default`): e.g. `ARG` is handled but a future/unknown directive
    like `STOPSIGNAL`... is handled; genuinely unknown ones like
    `HEREDOC`-style `RUN <<EOF` (parsed as RUN with args `<<EOF`),
    `EXPOSE` handled — unknown directives vanish without a trace.
  - Instructions before the first `FROM` (when `cur == nil`), except
    global `ARG`s.
  - `ARG` with an empty name; `WORKDIR` with empty args; `USER` with
    empty args; `CMD`/`ENTRYPOINT` with empty args.
  - `COPY` with zero or one non-flag field (no sources extracted).
  - Everything the adapter deliberately drops: ENV values, LABEL
    values, COPY destination, HEALTHCHECK command body, `ONBUILD`
    payload, `--platform`/`--from` flag operands, ARG defaults.

### 1.8 Known gaps (from reading)

1. No `${VAR}`/`$VAR` expansion or build-arg/default table — the biggest
   parity gap (see §1.6).
2. No `# syntax=` / BuildKit directive handling; heredoc `RUN <<EOF`
   bodies are kept as one raw string (`<<EOF`) — rules analyzing
   `run_commands` will see `<<EOF` as the body.
3. `total_stages` is back-patched in a post-loop mutation (`out[i]`),
   fine but notable for anyone consuming intermediate state.
4. Stage `Span.EndCol` is `1` (degenerate) — evidence spans point at the
   line only.
5. `add_span`/`maintainer_span` are typed as `Value{Raw: true}` bools
   carrying the span, not spans — consumers must know to read
   `.Span`, not `.Raw`.

---

## 2. Compose adapter (`internal/adapter/compose/`)

Adapter name: `"compose"` (`Adapter.Name()`). Source: `compose.go`
(311 lines). Tests: `compose_test.go`.

### 2.1 Entry point & detection

- `Adapter.Handles(path)` (`compose.go`, `Handles`): matches the
  lower-cased **basename** exactly against a fixed allow-list:
  - exact: `docker-compose.yml`, `docker-compose.yaml`,
    `compose.yml`, `compose.yaml`;
  - `docker-compose.<anything>.yml|yaml` (e.g.
    `docker-compose.prod.yml`);
  - `*.compose.yml` / `*.compose.yaml` (e.g. `app.compose.yaml`).
  - Rejects: `values.yaml`, `deployment.yml`, `a.json`, `Dockerfile`
    (verified in `TestHandles`).
- **Registration precedence is load-bearing.** `cmd/aegis/main.go`
  `defaultAdapters()` places `compose.New()` **before**
  `manifests.Adapter{}`, with the comment: "manifests claims every
  .yml/.yaml file, so compose files must be matched first." A
  `docker-compose.yml` would otherwise be parsed as Kubernetes
  manifests.
- Notably does **not** claim `podman-compose.yml` or other
  `<tool>-compose.yml` variants, nor bare `*.yml` service definitions.

### 2.2 High-level parse flow

1. `yaml.Unmarshal` (gopkg.in/yaml.v3) into a `yaml.Node` tree.
2. Requires a top-level mapping with a `services:` mapping; each service
   mapping becomes one `ir.Resource` via `parseService`.
3. All YAML navigation is by explicit `mappingGet` key lookup on
   `yaml.Node`s; scalars are rendered with `nodeString`, which returns
   `""` for non-scalars and for `!!null`.
4. `Parse` never returns a Go error for content problems — invalid YAML
   becomes an **error diagnostic** and `(nil, diags, nil)` is returned.

### 2.3 Type mapping

- Exactly one IR type: **`compose_service`**, Provider `"docker"`.
- One resource per entry under top-level `services:`.
- `Resource.Name` = the service key. Services with an empty name or a
  non-mapping value are **silently skipped** (`continue`, no diagnostic).
- Resource `Span`: the service mapping node's start line, degenerate
  columns (`StartCol: 1, EndCol: 1`, `EndLine == StartLine`) — sub-key
  spans are not tracked; all attributes reuse the service span.

### 2.4 Attribute mapping

Only the keys the adapter explicitly reads become attributes; **"Unknown
service keys are ignored"** (package doc) — silently. Mapped keys
(`parseService`):

| Attribute | Source / rule |
|---|---|
| `image` | `image:` scalar string; **absent** when missing/`null` |
| `privileged` | **always present** bool (`boolAttr`); `false` default when absent or unparsable (`strconv.ParseBool` failure → false, no diagnostic) |
| `cap_add` | `[]Value` of `cap_add:` sequence strings |
| `network_mode` | `network_mode:` scalar; absent when missing |
| `pid` | `pid:` scalar; absent when missing |
| `user` | `user:` scalar; absent when missing |
| `ports` | `[]Value` of `ports:` items **as raw strings** (`servicePorts`) — e.g. `"8080:80"` kept verbatim, including `443:443` (int renders via `nodeString` → `"443"`). **Long-syntax port mappings (sequence of mappings) are silently dropped**: `nodeString` returns `""` for non-scalar items and `servicePorts` filters empties |
| `volumes` | `[]Value` of **host-side source paths only** (`serviceVolumes`): short syntax split on the first `:` (so `/data/app:/app` → `/data/app`); named volumes (no `/` in source) are **kept anyway** with a comment noting rules only match absolute host paths; long syntax takes `source:` only. Container path and options (`ro`, `rw`, `z`) are dropped |
| `env_secrets` | `[]Value` of `{name, span}` maps for secret-looking env vars with literal non-empty values (`serviceEnvSecrets`); values redacted |

`environment:` is read in **both** mapping and sequence (`KEY=val`)
forms. Secret detection mirrors the Dockerfile adapter: same
`secretNameHints` list (`PASSWORD PASSWD SECRET TOKEN API_KEY APIKEY
PRIVATE_KEY PRIVATEKEY CREDENTIAL AUTH`, substring, case-insensitive),
value must be non-empty and contain no `$` after quote-stripping
(`isLiteralValue`). Only the name (plus span) is stored.

**Not mapped at all (silently ignored):** `build`, `command`,
`entrypoint`, `healthcheck`, `depends_on`, `restart`, `networks`
(except via `network_mode`), `expose`, `sysctls`, `dns`, `tmpfs`,
`secrets`, `configs`, `labels`, `logging`, `deploy` (incl.
`resources:` limits), `profiles`, `extends`, `working_dir`,
`container_name`, `hostname`, `domainname`, `stdin_open`, `tty`,
`read_only`, `security_opt`, `cap_drop`, `ulimits`, `env_file`,
`extra_hosts`, top-level `x-*` extensions, and any other key. The
package doc says "Unknown service keys are ignored" — there is no
diagnostic enumerating which keys were dropped.

### 2.5 Resolution

- **No variable substitution.** `${VAR}` / `$VAR` / `$$` in `image:`,
  `environment:`, `ports:`, `volumes:` are passed through verbatim
  (`nodeString` returns the raw scalar text). There is no `.env` file
  loading, no `env_file:` support, no default-value syntax
  (`${VAR:-default}`) evaluation.
- Types: YAML scalars keep their rendered string form (`nodeString`);
  `privileged: "yes"` parses via `strconv.ParseBool`; anything else is
  `false` with no warning.
- Like the Dockerfile adapter, **no `Known: false` values are ever
  emitted** and no `Ref`s — everything reported is `Known: true`.

### 2.6 Uncertainty policy

Same structural approach as the Dockerfile adapter (§1.6): uncertainty
is absence/empty/default-false, never `Known: false`. Consequences:

- A service without `image:` has no `image` attribute — indistinguishable
  from "image not applicable" (e.g. a `build:`-only service, whose `build:`
  context is itself ignored).
- `privileged` **always present**, defaulting to `false` even when the
  YAML value is garbage — a rule cannot distinguish "explicitly false"
  from "absent/unparsable".
- `${REGISTRY}/app:${TAG}` in `image:` is a *known* string; an
  image-tag-pinning rule sees it as a known untagged/tagged value.
- **Semantic-loss risk (MEDIUM):** `env_file:` is ignored entirely, so
  secrets injected via env files are invisible (arguably correct for a
  static scanner, but the *keys* aren't even recorded the way
  `env_names` are for Dockerfiles — the Dockerfile adapter records
  names, this one doesn't). `build:` context/dockerfile/args dropped
  means a compose service hides its Dockerfile linkage.

### 2.7 Diagnostics

- **Error** `"invalid YAML: …"` — malformed YAML; zero resources.
- **Warning** `"compose file has no top-level mapping"` — root is not a
  mapping (e.g. a bare list or scalar).
- **Warning** `"compose file has no services"` — missing or non-mapping
  `services:` (e.g. `version: "3"` alone, verified in
  `TestParseNoServices`).
- Parse never returns a non-nil Go error for content.
- **Silently skipped:** unnamed/non-mapping services; long-syntax
  `ports:` entries; every unmapped service key (no "ignored key" listing).

### 2.8 Known gaps (from reading)

1. No interpolation (`${VAR}`, `$VAR`, `${VAR:-default}`) and no
   `.env`/`env_file` support.
2. Long-syntax `ports:` silently dropped (only scalar items survive).
3. `volumes:` keeps named volumes (e.g. `dbdata`) in the same list as
   absolute host paths — downstream rules must filter (comment says
   rules only match absolute paths, but the mixing is a footgun).
4. Only the host *source* of volumes is kept; container path and
   `:ro`/`:rw` mode are dropped — a read-only rootfs/mount-mode rule
   cannot evaluate compose files.
5. `network_mode: "service:web"` / `"container:xyz"` pass through as
   strings (fine), but `networks:` aliases are invisible.
6. `deploy.resources` / `mem_limit` / `cpus` ignored — resource-limit
   rules have no compose input.
7. `healthcheck:` ignored — the compose analog of the Dockerfile
   `has_healthcheck` signal is missing; parity gap between the two
   docker adapters.
8. No `extends:`/`profiles:`/`include:` resolution.

---

## 3. Manifests adapter (`internal/adapter/manifests/`)

Adapter name: `"manifests"` (`Adapter.Name()`). Sources: `manifests.go`
(266 lines — Kubernetes path + dispatch) and `cfn.go` (485 lines —
CloudFormation normalization). Tests: `manifests_test.go`.

**Scope note:** despite the task framing ("Kubernetes manifests"), this
adapter handles **two** document families: Kubernetes manifests
(`k8s_<Kind>`) *and* CloudFormation templates (normalized to `aws_*` /
`cfn_*`). The package doc states this explicitly ("Scope (Milestone
5)"). The CFN path is a fallback: `defaultAdapters()` registers
`cloudformation.New()` *before* `manifests.Adapter{}`; the
cloudformation adapter claims files that sniff as CFN
(`looksLikeCFN`: contains `AWSTemplateFormatVersion` or a
`Resources:`/`Type: AWS::*` structure, via a bounded 1 MiB read).
Templates that fail that sniff but have a `Resources` mapping (e.g.
without `AWS::*` types) fall through to manifests' `isCFN`.

### 3.1 Entry point & detection

- `Adapter.Handles(path)` (`manifests.go`, `Handles`): matches the
  **lower-cased path string** (not just basename):
  - excludes `*.plan.json` (case-insensitive) — belongs to planjson;
    "The exclusion is defensive" (package comment; the CLI consults
    planjson first);
  - true for extensions `.yaml`, `.yml`, `.json`.
  - Verified in `TestHandles`: `a.YAML`, `dir/b.json`, `TEMPLATE.JSON`
    claimed; `a.tf`, `a.txt`, `a` rejected.
- **Broad claim = last resort.** It claims *every* `.yaml/.yml/.json`
  file, so registration order matters: compose, pulumi, arm, bicep, and
  cloudformation all precede it (`cmd/aegis/main.go`,
  `defaultAdapters`).

### 3.2 High-level parse flow

1. `decode(src)`: `.json` → single `encoding/json` document
   (`json.Unmarshal` into `any`); `.yaml`/`.yml` → multi-document
   `yaml.Decoder` loop. YAML sub-spans are **not** tracked.
2. `parseDocument(doc, idx)` per document (`idx` 0-based):
   - document must decode to a string-keyed map (`asStringMap`; YAML
     may yield `map[any]any`, which is converted; all-non-string keys
     fail the document);
   - has string `apiVersion` **and** string `kind` → **Kubernetes** path;
   - else `isCFN(m)`: has `AWSTemplateFormatVersion`, or a `Resources`
     mapping without K8s markers → **CloudFormation** path;
   - else → **warning** diagnostic `"manifests: unrecognized document N
     in <path>; skipped"`, no resource.
3. Spans are **approximations**: `ir.Span{File, StartLine: idx+1}` —
   the document *index* is used as the line number, documented as such
   in `parseDocument`'s comment ("an approximation, documented as such,
   since YAML sub-spans are not tracked").

### 3.3 Type mapping

**Kubernetes path** (`k8sResource`):
- Type: **`k8s_` + Kind verbatim**, e.g. `k8s_Deployment`,
  `k8s_Service` — note the Kind's original casing is preserved
  (`k8s_Deployment`, not `k8s_deployment`). Provider `"k8s"`.
- Name: `metadata.name`, or `"unnamed"` when absent/non-string.

**CloudFormation path** (`cfnResources` in `cfn.go`):
- Type: `normalizeType`: 9-entry `cfnTypeTable` maps to canonical AWS
  names consumed by the AWS rule pack —
  `AWS::S3::Bucket`→`aws_s3_bucket`,
  `AWS::S3::BucketPolicy`→`aws_s3_bucket_policy`,
  `AWS::EC2::SecurityGroup`→`aws_security_group`,
  `AWS::EC2::SecurityGroupIngress`→`aws_security_group_rule`,
  `AWS::RDS::DBInstance`→`aws_db_instance`,
  `AWS::EBS::Volume`→`aws_ebs_volume`,
  `AWS::IAM::Role`→`aws_iam_role`,
  `AWS::IAM::Policy`→`aws_iam_policy`,
  `AWS::CloudTrail::Trail`→`aws_cloudtrail`.
  Everything else → **`cfn_` + lowercased type with `::`→`_`**,
  e.g. `AWS::EC2::Instance` → `cfn_aws_ec2_instance` (verified in
  `TestNormalizeType`). Those `cfn_*` types match **no** AWS rules.
- Name: the template's logical resource ID. Provider `"aws"`.
- Resources emitted in **sorted logical-ID order** for determinism
  (`TestDeterminism`).

### 3.4 Attribute mapping

**Kubernetes path** — the whole document becomes attributes:
`k8sResource` iterates every top-level key (`apiVersion`, `kind`,
`metadata`, `spec`, …) and converts via `parser.value` → `ir.Value`
recursively. Lists → `[]Value`; maps → `map[string]ir.Value`. Scalars:
`bool`/`string` known; `int`/`int64` → **`float64`** (lossy above 2^53,
noted in `value`); `float64` known; `nil` → `ir.UnknownValue`.
Non-string map keys are **skipped with a single warning per file**
(`warnKeys`). There is no type-specific normalization at all — rule
authors navigate raw K8s shapes (e.g. `spec.template.spec.containers[].
securityContext.privileged`, as exercised in `TestParseK8sMultiDoc`).
No flattening, no renaming: attribute keys are the original YAML keys
(`securityContext`, not `security_context`).

**CloudFormation path** (`mapResource` in `cfn.go`) — property
normalization to the canonical shapes the AWS rule pack expects:
- `aws_s3_bucket`: `AccessControl`→`acl` (via `aclName`: Private→
  `private`, PublicRead→`public-read`, PublicReadWrite→
  `public-read-write`; unknown values pass through verbatim);
  `BucketEncryption`→`server_side_encryption_configuration = "cfn"`
  (presence marker — "the rule pack treats a present-but-opaque block
  as 'cannot decide'"); `VersioningConfiguration`→
  `versioning: {enabled: bool}`; `PublicAccessBlockConfiguration`→
  `__cfn_public_access_block: true` (double-underscore private attr);
  `LoggingConfiguration`→`logging: [{target_bucket: …}]` (Terraform-style
  block so rule 445 can evaluate it; only when
  `DestinationBucketName` is a non-empty string).
- `aws_s3_bucket_policy`: `PolicyDocument`→`policy` (**JSON string**,
  rendered by `jsonString` after intrinsic resolution);
  `Bucket`→`bucket`.
- `aws_security_group`: `GroupDescription`→`description`;
  `SecurityGroupIngress`/`SecurityGroupEgress`→`ingress`/`egress` via
  `ingressRules` → `[]Value` of `{protocol, from_port, to_port,
  cidr_blocks}` maps.
- `aws_security_group_rule` (standalone `AWS::EC2::SecurityGroupIngress`):
  `type = "ingress"` hard-coded; `IpProtocol`→`protocol`,
  `FromPort`→`from_port`, `ToPort`→`to_port`, `CidrIp`/`CidrIpv6`
  accumulated into `cidr_blocks`, `GroupId`→`security_group_id`.
- `aws_db_instance`: `StorageEncrypted`→`storage_encrypted`,
  `DeletionProtection`→`deletion_protection`,
  `PubliclyAccessible`→`publicly_accessible`.
- `aws_iam_role`/`aws_iam_policy`: `AssumeRolePolicyDocument`/
  `PolicyDocument`→`assume_role_policy`/`policy` as JSON strings.
- `aws_cloudtrail`: `EnableLogFileValidation`→
  `enable_log_file_validation`.
- **Unmapped properties pass through verbatim with keys snake_cased**
  via `snake()` (`DBInstanceClass`→`db_instance_class`,
  `BucketName`→`bucket_name`; runs of capitals treated as one word).
  Unmapped types (the `cfn_*` fallback) pass *all* properties through
  with snake_cased keys.

Policy-document JSON rendering (`jsonString`/`valueToGo`): the resolved
value is converted back to Go natives and `json.Marshal`ed. **Anything
unresolvable makes the whole document `Unknown`** ("rather than a
half-rendered lie").

### 3.5 Resolution

**Kubernetes path:** no resolution at all — pure structural conversion.
Helm/Go-template markers (`{{ .Values.x }}`), `$(VAR)` env references,
and Kustomize patches are kept as literal strings. YAML anchors/aliases
are resolved by the YAML library itself (standard).

**CloudFormation path** (`cfnCtx`):
- **Parameters collected first**: each parameter's `Default`, when a
  static scalar (string/bool/number; lists/maps/intrinsics are *not*
  static), becomes the resolved value; parameters without `Default`
  resolve to `Unknown`.
- **`Ref`**: to a parameter → its default (possibly `Unknown`); to a
  resource logical ID → `Value{Known: false, Ref: "<normtype>.<id>"}`
  (e.g. `Ref: "DataBucket"` → `Ref: "aws_s3_bucket.DataBucket"`);
  empty/non-string target or unknown name → plain `Unknown` (no `Ref`).
- **`Fn::GetAtt`**: string form (`"B.Arn"` → target `B`) and list form
  (`["B", "Arn"]` → target `B`) → `Known: false, Ref:
  "<normtype>.<target>"`; unknown target → plain `Unknown`.
- **Every other intrinsic** (`Fn::Join`, `Fn::Sub`, `Fn::If`,
  `Fn::ImportValue`, …) → **explicit `Unknown`** — "intrinsics are
  never evaluated" (comment on `cfnCtx.value`). Single-key maps that
  are *not* `Ref`/`Fn::GetAtt`/`Fn::*` (e.g. a literal
  `{"a": 1}`… actually any single-key non-intrinsic map) fall through
  to recursive map conversion — handled correctly.
- Intrinsics resolve **recursively** inside lists and maps.
- `Condition`, `DependsOn`, `Metadata`, `CreationPolicy`, etc. are
  ignored (unmapped → snake_case passthrough for properties, but
  top-level resource keys other than `Type`/`Properties` are dropped —
  `cfnResources` only reads `Type` and `Properties`).

### 3.6 Uncertainty policy

This adapter is the only one of the three that uses the IR's
uncertainty machinery properly:

- YAML/JSON `null` → `ir.UnknownValue` (explicit, not zero-value).
- Unresolvable CFN intrinsics → `Known: false`; resource `Ref`s carry
  `Ref: "<type>.<logicalId>"` so the semantics layer can resolve them
  later (consistent with the `ir.Value` contract: "Known is always false
  when Ref is set").
- CFN parameter `Ref` → the parameter's default, or `Unknown` when no
  default.
- **Semantic-loss risk (MEDIUM):** `BucketEncryption` presence is
  collapsed to the string `"cfn"` (`server_side_encryption_configuration
  = "cfn"`). The actual algorithm/KMS key are discarded, so an
  SSE-KMS-vs-SSE-S3 rule sees "cannot decide" at best; the comment says
  this is deliberate. Similarly `PublicAccessBlockConfiguration` is
  collapsed to `__cfn_public_access_block: true` — the four individual
  block flags are lost, so a rule distinguishing
  `block_public_acls` from `block_public_policy` cannot evaluate.
- `VersioningConfiguration.Status != "Enabled"` → `enabled: false`
  (known false) — `Suspended` is conflated with "never enabled".
- K8s: non-string map keys are **skipped silently after the first
  warning per file** — the rest of the map is kept, so a rule sees a
  partial map with no per-key trace of what was dropped.

### 3.7 Diagnostics

- **Error** `"manifests: invalid JSON: …"` — unparseable `.json`;
  decode stops, zero resources.
- **Error** `"manifests: invalid YAML: …"` — a YAML document fails to
  decode; decode stops (later documents in the stream are not
  attempted).
- **Warning** `"manifests: unrecognized document N in <path>; skipped"`
  — per document that is neither K8s-shaped nor CFN-shaped (e.g.
  `foo: bar`, `just a string`, `123`, `[]`, `null` — all covered in
  `TestNoPanicSweep`; empty `---` documents are skipped *silently*).
- **Warning** `"manifests: resource %q is not a mapping; skipped"` —
  CFN `Resources` entry that isn't a map (e.g. `"B": null`).
- **Warning** `"manifests: non-string map key skipped in <path>"` —
  emitted **once per file** even if many keys are dropped.
- "Content problems never produce a hard error" (package doc on
  `Parse`): `Parse` itself returns `nil` error in all paths; all
  problems surface as diagnostics. Multi-document YAML bombs are
  "bounded by the discovery layer's file-size caps (documented here,
  enforced there)" — i.e. not enforced in this adapter.

### 3.8 Known gaps (from reading)

1. **K8s attribute keys are not normalized** (camelCase preserved:
   `securityContext`, `readOnlyRootFilesystem`) while the CFN path
   snake_cases everything — a rule pack spanning both must handle two
   conventions. K8s types keep the original Kind casing
   (`k8s_Deployment`), so `AppliesTo` matching is case-sensitive by
   construction.
2. **Spans are document-index approximations** (`StartLine: idx+1`);
   there is no line information for any K8s field or CFN property —
   evidence will point at the wrong line for multi-document files.
   K8s decoding via `yaml.Decoder` into `any` discards node positions
   entirely (unlike the compose adapter, which keeps `yaml.Node`s).
3. Only 9 CFN types are normalized; everything else becomes `cfn_*`
   with **no rule coverage** — silently unscanned for AWS rules
   (though the resources still exist in the IR).
4. `Fn::If`/`Conditions` are unevaluated → `Unknown`, which is honest
   but means condition-gated security settings (e.g. encryption enabled
   only in prod) are invisible to rules.
5. Numbers: YAML `int`/`int64` become `float64` — fine for ports, lossy
   for large integers; JSON numbers are already `float64`.
6. CFN `UpdatePolicy`, `DeletionPolicy`, `Metadata`, `DependsOn`,
   `Condition` on resources are dropped (only `Type`/`Properties`
   read). `Outputs`/`Mappings` sections ignored — `Fn::FindInMap`
   → `Unknown`.
7. `isCFN` treats *any* doc with a `Resources` mapping as CFN even
   without `AWSTemplateFormatVersion` — a K8s-adjacent custom YAML
   with a top-level `Resources:` key would be misclassified (edge case;
   the dedicated cloudformation adapter's stricter sniff runs first).

---

## Cross-adapter observations (parity-relevant)

1. **Uncertainty is inconsistent across adapters.** The manifests
   adapter uses `Known: false`/`Ref`/`UnknownValue` per the IR contract;
   the dockerfile and compose adapters *never* emit `Known: false` —
   unresolved `${VAR}` interpolations are reported as **known strings
   containing `$…`**. A rule that trusts `Known` will mis-evaluate
   Dockerfile/Compose inputs while handling K8s/CFN correctly.
2. **Secret redaction is consistent** (names only, `{name, span}` maps,
   same hint list) between dockerfile (`ENV`/`ARG`) and compose
   (`environment:`) — but compose has no analog of dockerfile's
   `env_names`/`arg_names` (non-secret names are dropped), and compose
   ignores `env_file:` entirely.
3. **Span fidelity degrades across adapters:** dockerfile and compose
   give real (if degenerate, column-1) line spans per construct;
   manifests gives only a document-index pseudo-line (`StartLine:
   idx+1`) with no column/field information.
4. **Health signals are asymmetric:** dockerfile records
   `has_healthcheck`; compose ignores `healthcheck:` — the two docker
   adapters disagree on what a container's liveness story looks like.
5. **`Handles` overlap is managed by registration order, not by the
   adapters themselves:** compose must precede manifests (both match
   `docker-compose.yml`); cloudformation must precede manifests (both
   match CFN templates). The `.plan.json` exclusion is duplicated in
   both manifests and cloudformation as defense-in-depth.
6. **Silent-drop inventory (no diagnostic anywhere):** unknown
   Dockerfile instructions; pre-`FROM` instructions; COPY/ADD
   destinations; ENV/LABEL values; ARG defaults; compose service keys
   outside the 9 mapped ones; compose long-syntax ports; unnamed
   compose services; K8s non-string map keys after the first warning;
   CFN unmapped resource-level keys (`DeletionPolicy`, `Condition`,
   `Metadata`, `Outputs`, `Mappings`).
