# CloudFormation Support

Aegis scans AWS CloudFormation templates (JSON and YAML) by converting
them into the canonical IR with Terraform-style resource types, so the
entire AWS rule pack applies with zero new rules.

## Detection

`aegis scan` auto-detects CloudFormation templates by content sniffing:
a file is claimed by the CloudFormation adapter when it has a `.yaml`,
`.yml`, `.json`, or `.template` extension (excluding `.plan.json`) AND
contains `AWSTemplateFormatVersion` or a `Resources:` mapping with
`Type: AWS::*` entries. Kubernetes manifests and other YAML/JSON files
fall through to the manifests adapter untouched.

The adapter is registered before `manifests.Adapter` in
`defaultAdapters()` (`cmd/aegis/main.go`).

## Type mapping

`internal/adapter/cloudformation/typemap.go` maps 100 CloudFormation
resource types to Terraform equivalents, e.g.:

| CloudFormation | Terraform |
|---|---|
| `AWS::S3::Bucket` | `aws_s3_bucket` |
| `AWS::EC2::SecurityGroup` | `aws_security_group` |
| `AWS::IAM::Role` | `aws_iam_role` |
| `AWS::RDS::DBInstance` | `aws_db_instance` |
| `AWS::Lambda::Function` | `aws_lambda_function` |
| `AWS::KMS::Key` | `aws_kms_key` |

Unmapped types are skipped with a warning diagnostic (never silent).

## Property mapping

Properties are converted PascalCase → snake_case recursively. Resources
whose CloudFormation structure differs from Terraform's get dedicated
converters (`props.go`):

- **S3**: `BucketEncryption` → `server_side_encryption_configuration`
  (Terraform block shape); `VersioningConfiguration` →
  `versioning {enabled}`; `LoggingConfiguration` → `logging`;
  `PublicAccessBlockConfiguration` → synthesized
  `aws_s3_bucket_public_access_block` companion resource.
- **IAM Role/Policy/User, KMS Key**: policy documents (maps) are
  JSON-encoded into `assume_role_policy` / `policy` string attributes,
  matching what the IAM rules parse. Inline role/user policies become
  `aws_iam_role_policy` / `aws_iam_user_policy` companions.
- **Security Groups**: `SecurityGroupIngress/Egress` →
  `ingress`/`egress` blocks with `cidr_blocks`.
- **RDS, CloudTrail, DynamoDB, ElastiCache, Redshift, OpenSearch**:
  key renames (`IsLogging` → `enable_logging`, `SSESpecification` →
  `server_side_encryption`, ...).

## Intrinsic functions

| Intrinsic | Behavior |
|---|---|
| `Ref: Param` (with Default) | resolved to the default |
| `Ref: Param` (no default) | UnknownValue, `Ref: cfn.parameter.<Name>` |
| `Ref: AWS::*` (pseudo-params) | UnknownValue |
| `Ref: LogicalId` / `Fn::GetAtt` | UnknownValue (`cfn.resource.*` / `cfn.getatt.*`) |
| `Fn::Join`, `Fn::Sub` | resolved when all parts are static |
| `Fn::If`, `Fn::ImportValue`, `Fn::FindInMap`, ... | UnknownValue |
| `!Ref`, `!Join`, `!Sub`, `!GetAtt` shorthand | same as long form |

Unknown values are never guessed: rules treat them as undecidable.

## Parameters, Mappings, Conditions, Outputs

- **Parameters**: defaults become known values; parameters without
  defaults are explicitly unknown.
- **Mappings**: not resolved (warning diagnostic); `Fn::FindInMap`
  yields unknown.
- **Conditions**: not evaluated; resources are still converted.
- **Outputs**: converted to synthetic `cfn_output` resources (same
  pattern as the Terraform adapter's `terraform_output`).

## Scan completeness

Malformed templates produce error diagnostics, never panics or silent
skips. Unmapped resource types produce warning diagnostics naming the
type and logical ID.

## Tests

`internal/adapter/cloudformation/cfn_test.go`: 15 tests covering
detection, S3/IAM/EC2/RDS vulnerable+secure pairs, JSON templates,
intrinsic resolution (`Ref`/`Join`/`Sub`), unknown parameters, unmapped
types, malformed input, and outputs.
