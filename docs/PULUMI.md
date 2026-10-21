# Pulumi YAML Support

Aegis scans declarative **Pulumi YAML programs** (`Pulumi.yaml` / `Pulumi.yml`)
by normalizing them to the same canonical resource types the Terraform rule
packs consume. A vulnerable S3 bucket declared in Pulumi YAML trips the same
rules as the equivalent Terraform.

## What is supported

- `Pulumi.yaml` files (any case: `Pulumi.yml`, `PULUMI.YAML`, ...)
- The `resources:` section: `type:`, `properties:`, `options:`
- `variables:` and `configuration:` (including `default:` values) for
  `${...}` reference resolution
- 150+ Pulumi type tokens mapped across AWS (`aws:`), Azure
  (`azure-native:`), and GCP (`gcp:`) — see
  `internal/adapter/pulumi/typemap.go` for the full table
- camelCase property names are converted to snake_case
  (`serverSideEncryptionConfiguration` → `server_side_encryption_configuration`)
  so Terraform-oriented rules keep working
- Pulumi intrinsics (`fn::invoke`, `fn::secret`, ...) become explicit
  Unknown values with warning diagnostics — never silently treated as safe
- Secret `configuration:` entries without defaults stay Unknown

## Example

```yaml
name: my-project
runtime: yaml
resources:
  data:
    type: aws:s3:Bucket
    properties:
      bucket: my-data
      acl: public-read   # AEGIS-AWS-002 fires, same as Terraform
```

```sh
aegis scan ./my-pulumi-project --format=json
```

The scan completeness report shows `"format": "pulumi"` per file, and mixed
directories (`.tf` + `Pulumi.yaml` + `Dockerfile` + Kubernetes manifests)
are scanned in a single run.

## Honest scope note

**Pulumi programs written in TypeScript, Python, Go, or .NET are not
supported.** Those require language runtimes to evaluate; a static scanner
cannot resolve them without executing code, which Aegis never does. Pulumi
YAML covers the declarative use case. If you need imperative Pulumi
languages, convert with `pulumi convert` or scan the deployed state.

**Imperative Pulumi programs warn instead of scanning silently.**
When the scanner detects a Pulumi program in TypeScript/JavaScript,
Python, Go, .NET, or Java (`Pulumi.yaml` with `runtime: nodejs`,
`python`, `go`, `dotnet`, or `java`/`jvm` — or, when the runtime field is
absent, the language's marker files alongside program entrypoints), it
emits a warning diagnostic naming the unparsed program files — so
"0 findings" can never be misread as "clean". Pulumi YAML is analyzed
declaratively and never warns.

## Project config file (aegis.yaml)

`aegis scan --config aegis.yaml` loads per-project settings:

```yaml
# Downgrade a noisy rule, escalate what matters to you.
severity_overrides:
  AEGIS-AWS-001: low
  AEGIS-AWS-004: critical

# Drop rules entirely for this project.
exclude_rules:
  - AEGIS-AWS-558
```

- Overrides apply at report time: rule ID, evidence, and remediation are
  unchanged; only the reported severity changes (which also affects
  `--fail-on` and the exit code).
- Invalid severities and overrides that match no findings produce warning
  diagnostics — a stale config can never break a scan.

## Excluding paths

```sh
aegis scan ./infra --exclude="vendor/**,*.tfvars,docs/*.md"
```

Glob syntax: `*` matches within a path segment, `**` crosses segments,
`?` matches one character. Patterns without a leading slash match at any
depth (gitignore-style). Excluded files are reported as `skipped` with an
explicit reason in scan completeness.

## Compliance filtering and summaries

```sh
aegis scan ./infra --compliance=CIS-AWS-1.5
```

Filters findings to the requested framework (`CIS-AWS-1.5`, `NIST-800-53`,
`PCI-DSS-4.0`) and prints a per-control pass/fail summary:

```
compliance CIS-AWS-1.5: 42/50 controls passing — FAILING: 1.8, 2.1.1, 3.2
```

The summary is also present in JSON output as `compliance_summary`.
