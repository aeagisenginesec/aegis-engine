// Package rules — remediation guidance and documentation links.
//
// RemediationFor maps rule IDs to concrete fix steps (Terraform snippets)
// and documentation URLs. EnrichRemediation attaches them to findings at
// report time, mirroring EnrichCompliance. Rules never set these directly.
//
// Coverage: detailed entries for all Critical rules and the highest-impact
// High rules. Everything else falls back to category-aware templates derived
// from the rule title, so no finding ever ships without guidance.
package rules

import (
	"strings"
	"sync"

	"aegis/internal/ir"
)

// remediationEntry holds fix steps and doc links for one rule.
type remediationEntry struct {
	fix  string
	refs []string
}

// RemediationFor returns the fix steps and documentation URLs for a rule.
// Falls back to a category-aware template when no detailed entry exists.
func RemediationFor(ruleID string) (string, []string) {
	if e, ok := remediationDB[ruleID]; ok {
		return e.fix, e.refs
	}
	return fallbackRemediation(ruleID)
}

// EnrichRemediation attaches remediation guidance and doc links to each finding.
func EnrichRemediation(findings []ir.Finding) []ir.Finding {
	for i := range findings {
		fix, refs := RemediationFor(findings[i].RuleID)
		findings[i].Remediation = fix
		findings[i].References = refs
	}
	return findings
}

// fallbackRemediation generates category-aware guidance from the rule ID
// prefix and title keywords. Never returns empty.
func fallbackRemediation(ruleID string) (string, []string) {
	lower := strings.ToLower(ruleID)
	_ = lower
	title := ruleTitle(ruleID)
	t := strings.ToLower(title)

	switch {
	case containsAny(t, []string{"encrypt", "kms", "sse"}):
		return "Enable encryption at rest. For AWS-managed keys add the service's " +
				"encryption block (e.g. `storage_encrypted = true` for RDS, " +
				"`server_side_encryption_configuration` for S3). For regulated data use " +
				"a customer-managed KMS key via `kms_key_id` and enable key rotation.",
			[]string{"https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html"}
	case containsAny(t, []string{"public", "open to the world", "0.0.0.0", "internet-facing", "exposure"}):
		return "Remove public exposure. Restrict ingress to known CIDR ranges, move the " +
				"resource into private subnets, and front it with a load balancer or API " +
				"gateway if external access is required. Verify with `aws ec2 describe-security-groups`.",
			[]string{"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"}
	case containsAny(t, []string{"iam", "policy", "privilege", "assume", "role"}):
		return "Apply least privilege. Replace wildcard (`*`) actions and resources with the " +
				"minimum scoped ARNs the workload needs. Split policy authoring from attachment. " +
				"Use IAM Access Analyzer to generate scoped policies from CloudTrail history.",
			[]string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"}
	case containsAny(t, []string{"log", "trail", "audit", "monitor", "alarm", "metric"}):
		return "Enable audit logging. Turn on CloudTrail (multi-region, log file validation, " +
				"KMS-encrypted bucket), VPC flow logs, and service access logs. Ship logs to a " +
				"dedicated, MFA-delete-protected bucket in a security account.",
			[]string{"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html"}
	case containsAny(t, []string{"secret", "password", "credential", "token", "hardcoded"}):
		return "Remove the hardcoded secret immediately and rotate it. Store secrets in AWS " +
				"Secrets Manager or SSM Parameter Store (SecureString) and reference them via " +
				"data sources. Never commit secrets to version control — scan history with " +
				"gitleaks if the value was ever committed.",
			[]string{"https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html"}
	case containsAny(t, []string{"tls", "ssl", "https", "http", "plaintext"}):
		return "Enforce TLS 1.2+. Replace HTTP listeners with HTTPS, set a modern TLS policy " +
				"(e.g. `ELBSecurityPolicy-TLS13-1-2-2021-06`), and redirect HTTP→HTTPS. " +
				"Disable weak ciphers and old protocol versions everywhere.",
			[]string{"https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-security-policy-table.html"}
	case containsAny(t, []string{"versioning", "backup", "retention", "pitr", "snapshot"}):
		return "Enable data protection. Turn on versioning / point-in-time recovery / automated " +
				"backups with a retention period ≥ 7 days (30+ for production). Test restores " +
				"regularly — untested backups are not backups.",
			[]string{"https://docs.aws.amazon.com/aws-backup/latest/devguide/whatisbackup.html"}
	case containsAny(t, []string{"deletion protection", "termination protection", "force_destroy"}):
		return "Enable deletion protection to prevent accidental destruction:\n" +
				"resource \"aws_db_instance\" \"this\" {\n" +
				"  deletion_protection = true\n" +
				"}\n" +
				"For S3, remove `force_destroy = true`. For EC2, set " +
				"`disable_api_termination = true`.",
			[]string{"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html"}
	case containsAny(t, []string{"multi-az", "multi_az", "availability zone"}):
		return "Enable Multi-AZ for high availability and automatic failover:\n" +
				"resource \"aws_db_instance\" \"this\" {\n" +
				"  multi_az = true\n" +
				"}",
			[]string{"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html"}
	case containsAny(t, []string{"waf"}):
		return "Attach a WAFv2 Web ACL with managed rule groups (AWSManagedRulesCommonRuleSet,\n" +
				"AWSManagedRulesKnownBadInputsRuleSet) to the load balancer / API / distribution.\n" +
				"Set the default action to block and monitor via CloudWatch metrics.",
			[]string{"https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html"}
	case containsAny(t, []string{"rotation"}):
		return "Enable automatic rotation. For KMS: `enable_key_rotation = true`. For secrets:\n" +
				"configure Secrets Manager rotation with a Lambda function on a 30-day schedule.\n" +
				"For IAM keys: rotate every 90 days and prefer short-lived credentials.",
			[]string{"https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html"}
	case containsAny(t, []string{"mfa", "root"}):
		return "Enable MFA on the account and restrict root usage. Create individual IAM users " +
				"or federate via SSO, attach least-privilege policies, and never use root for " +
				"daily operations.",
			[]string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"}
	default:
		return "Review the flagged configuration against AWS security best practices and the " +
				"CIS AWS Foundations Benchmark. Apply the control the rule describes, preferring " +
				"restrictive defaults, encryption, and audit logging. Validate with `aegis scan` " +
				"after the change.",
			[]string{"https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html"}
	}
}

// ruleTitle looks up a rule's title from the default registry for fallback text.
func ruleTitle(ruleID string) string {
	titleCacheOnce.Do(func() {
		titleCache = make(map[string]string, 600)
		for _, r := range DefaultRegistry().All() {
			titleCache[r.ID()] = r.Title()
		}
	})
	if t, ok := titleCache[ruleID]; ok {
		return t
	}
	return ""
}

var (
	titleCacheOnce sync.Once
	titleCache     map[string]string
)

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// remediationDB holds detailed fix steps for Critical rules and the
// highest-impact High rules. Keys are rule IDs.
var remediationDB = map[string]remediationEntry{
	// ------------------------------------------------------------------
	// CRITICAL
	// ------------------------------------------------------------------
	"AEGIS-AWS-003": {
		fix: "Remove the public principal from the bucket policy. Replace\n" +
			"`\"Principal\": \"*\"` with specific IAM ARNs, or delete the policy " +
			"statement entirely if public access was unintentional. Then enable all four\n" +
			"public-access-block settings:\n" +
			"resource \"aws_s3_bucket_public_access_block\" \"this\" {\n" +
			"  bucket                  = aws_s3_bucket.this.id\n" +
			"  block_public_acls       = true\n" +
			"  block_public_policy     = true\n" +
			"  ignore_public_acls      = true\n" +
			"  restrict_public_buckets = true\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
	},
	"AEGIS-AWS-006": {
		fix: "Replace the wildcard policy with least-privilege statements. List only the\n" +
			"actions the workload needs on only the ARNs it touches:\n" +
			"policy = jsonencode({\n" +
			"  Version = \"2012-10-17\"\n" +
			"  Statement = [{\n" +
			"    Effect   = \"Allow\"\n" +
			"    Action   = [\"s3:GetObject\", \"s3:PutObject\"]\n" +
			"    Resource = [\"arn:aws:s3:::my-bucket/*\"]\n" +
			"  }]\n" +
			"})\n" +
			"Use IAM Access Analyzer policy generation from CloudTrail to derive the minimum set.",
		refs: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
		},
	},
	"AEGIS-AWS-101": {
		fix: "Lock down the role trust policy. Replace the wildcard principal with the\n" +
			"specific IAM ARNs or federated providers allowed to assume the role, and add\n" +
			"a condition such as `aws:PrincipalOrgID` or `sts:ExternalId`:\n" +
			"assume_role_policy = jsonencode({\n" +
			"  Version = \"2012-10-17\"\n" +
			"  Statement = [{\n" +
			"    Effect    = \"Allow\"\n" +
			"    Principal = { AWS = \"arn:aws:iam::123456789012:role/DeployRole\" }\n" +
			"    Action    = \"sts:AssumeRole\"\n" +
			"    Condition = { StringEquals = { \"sts:ExternalId\" = \"unique-value\" } }\n" +
			"  }]\n" +
			"})",
		refs: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html",
		},
	},
	"AEGIS-AWS-104": {
		fix: "Break the public exfiltration path. Make the S3 bucket private (see AEGIS-AWS-003\n" +
			"fix), remove the overly permissive IAM policy (see AEGIS-AWS-006 fix), and\n" +
			"ensure the compute role cannot reach public buckets. Treat this as an active\n" +
			"incident path: audit CloudTrail for `s3:GetObject` calls from the affected role.",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
		},
	},
	"AEGIS-AWS-202": {
		fix: "Replace the HTTP listener with HTTPS. Create an ACM certificate and attach it:\n" +
			"resource \"aws_lb_listener\" \"https\" {\n" +
			"  load_balancer_arn = aws_lb.this.arn\n" +
			"  port              = 443\n" +
			"  protocol          = \"HTTPS\"\n" +
			"  ssl_policy        = \"ELBSecurityPolicy-TLS13-1-2-2021-06\"\n" +
			"  certificate_arn   = aws_acm_certificate.this.arn\n" +
			"  default_action { type = \"forward\" target_group_arn = aws_lb_target_group.this.arn }\n" +
			"}\n" +
			"Add an HTTP listener that redirects to HTTPS (301).",
		refs: []string{
			"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html",
		},
	},
	"AEGIS-AWS-501": {
		fix: "Split policy authoring from attachment (this combination is the classic privilege\n" +
			"escalation primitive). Remove `iam:CreatePolicy*` / `iam:Attach*Policy` from the\n" +
			"workload policy. Policy management belongs in a separate, human-gated CI/CD role —\n" +
			"never in an application runtime role.",
		refs: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
		},
	},
	"AEGIS-AWS-502": {
		fix: "Scope `iam:PassRole` to the exact role ARNs the workload must pass, and only\n" +
			"together with the specific compute-launch action it needs:\n" +
			"{\n" +
			"  \"Effect\": \"Allow\",\n" +
			"  \"Action\": \"iam:PassRole\",\n" +
			"  \"Resource\": \"arn:aws:iam::123456789012:role/AppExecutionRole\"\n" +
			"}\n" +
			"Never grant `iam:PassRole` on `*` — it lets the holder escalate to any role.",
		refs: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html",
		},
	},
	"AEGIS-AWS-534": {
		fix: "Remove secrets from user_data immediately and rotate every exposed value.\n" +
			"Pass secrets via instance tags + Secrets Manager lookup at boot, or use an IAM\n" +
			"instance profile so the instance fetches secrets at runtime:\n" +
			"user_data = base64encode(templatefile(\"bootstrap.sh\", {}))  # no secrets inside\n" +
			"Note: user_data is visible to anyone with EC2 DescribeInstances — treat any\n" +
			"secret ever placed there as compromised.",
		refs: []string{
			"https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html",
		},
	},
	"AEGIS-AWS-629": {
		fix: "Break the kill chain at the cheapest hop. Recommended order:\n" +
			"1. Close the entry point (restrict the security group / remove public ingress).\n" +
			"2. Scope the IAM role to least privilege (see AEGIS-AWS-006 fix).\n" +
			"3. Move the data store to private subnets with no public route.\n" +
			"Re-run `aegis scan --attack-paths` to confirm the chain is gone.",
		refs: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",
		},
	},
	"AEGIS-GCP-001": {
		fix: "Remove `allUsers` / `allAuthenticatedUsers` from the bucket IAM policy. Grant\n" +
			"`roles/storage.objectViewer` only to specific service accounts or groups:\n" +
			"resource \"google_storage_bucket_iam_member\" \"viewer\" {\n" +
			"  bucket = google_storage_bucket.this.name\n" +
			"  role   = \"roles/storage.objectViewer\"\n" +
			"  member = \"serviceAccount:app@project.iam.gserviceaccount.com\"\n" +
			"}",
		refs: []string{
			"https://cloud.google.com/storage/docs/access-control/iam-roles",
		},
	},
	"AEGIS-GCP-148": {
		fix: "Remove primitive basic roles (roles/owner, roles/editor, roles/viewer) from the organization IAM policy. Replace with least-privilege predefined roles:\n" +
			"resource \"google_organization_iam_member\" \"least_priv\" {\n" +
			"  org_id = \"123456789\"\n" +
			"  role   = \"roles/resourcemanager.organizationViewer\"\n" +
			"  member = \"group:security@example.com\"\n" +
			"}",
		refs: []string{
			"https://cloud.google.com/iam/docs/understanding-roles#basic",
		},
	},
	"AEGIS-GCP-185": {
		fix: "Remove the public binding from the bucket IAM policy. Grant access only to specific principals:\n" +
			"resource \"google_storage_bucket_iam_member\" \"viewer\" {\n" +
			"  bucket = google_storage_bucket.this.name\n" +
			"  role   = \"roles/storage.objectViewer\"\n" +
			"  member = \"serviceAccount:app@project.iam.gserviceaccount.com\"\n" +
			"}",
		refs: []string{
			"https://cloud.google.com/storage/docs/access-control/iam-roles",
		},
	},
	"AEGIS-GCP-186": {
		fix: "Remove public entries from the default object ACL. Use uniform bucket-level access instead:\n" +
			"resource \"google_storage_bucket\" \"this\" {\n" +
			"  name                        = \"my-bucket\"\n" +
			"  uniform_bucket_level_access = true\n" +
			"}",
		refs: []string{
			"https://cloud.google.com/storage/docs/uniform-bucket-level-access",
		},
	},
	"AEGIS-GCP-190": {
		fix: "Remove public write bindings (roles/storage.objectCreator, roles/storage.admin) from the bucket IAM policy. Writing should require authentication:\n" +
			"resource \"google_storage_bucket_iam_member\" \"writer\" {\n" +
			"  bucket = google_storage_bucket.this.name\n" +
			"  role   = \"roles/storage.objectCreator\"\n" +
			"  member = \"serviceAccount:uploader@project.iam.gserviceaccount.com\"\n" +
			"}",
		refs: []string{
			"https://cloud.google.com/storage/docs/access-control/iam-roles",
		},
	},
	"AEGIS-GCP-192": {
		fix: "Remove public bindings from the table IAM policy. Grant BigQuery Data Viewer to specific principals:\n" +
			"resource \"google_bigquery_table_iam_member\" \"viewer\" {\n" +
			"  dataset_id = google_bigquery_dataset.this.dataset_id\n" +
			"  table_id   = google_bigquery_table.this.table_id\n" +
			"  role       = \"roles/bigquery.dataViewer\"\n" +
			"  member     = \"group:analysts@example.com\"\n" +
			"}",
		refs: []string{
			"https://cloud.google.com/bigquery/docs/access-control",
		},
	},
	"AEGIS-GCP-205": {
		fix: "Remove public bindings from the subscription IAM policy. Grant Pub/Sub Subscriber to specific service accounts:\n" +
			"resource \"google_pubsub_subscription_iam_member\" \"sub\" {\n" +
			"  subscription = google_pubsub_subscription.this.name\n" +
			"  role         = \"roles/pubsub.subscriber\"\n" +
			"  member       = \"serviceAccount:consumer@project.iam.gserviceaccount.com\"\n" +
			"}",
		refs: []string{
			"https://cloud.google.com/pubsub/docs/access-control",
		},
	},
	"AEGIS-GCP-226": {
		fix: "Remove public bindings from the secret IAM policy. Grant Secret Manager Secret Accessor to specific principals:\n" +
			"resource \"google_secret_manager_secret_iam_member\" \"accessor\" {\n" +
			"  secret_id = google_secret_manager_secret.this.secret_id\n" +
			"  role      = \"roles/secretmanager.secretAccessor\"\n" +
			"  member    = \"serviceAccount:app@project.iam.gserviceaccount.com\"\n" +
			"}",
		refs: []string{
			"https://cloud.google.com/secret-manager/docs/access-control",
		},
	},
	"AEGIS-GCP-260": {
		fix: "Remove public bindings from the repository IAM policy. Grant Artifact Registry Reader to specific principals:\n" +
			"resource \"google_artifact_registry_repository_iam_member\" \"reader\" {\n" +
			"  repository = google_artifact_registry_repository.this.name\n" +
			"  role       = \"roles/artifactregistry.reader\"\n" +
			"  member     = \"serviceAccount:ci@project.iam.gserviceaccount.com\"\n" +
			"}",
		refs: []string{
			"https://cloud.google.com/artifact-registry/docs/access-control",
		},
	},
	"AEGIS-K8S-001": {
		fix: "Drop privileged mode. Remove `securityContext.privileged: true` and use the\n" +
			"minimum Linux capabilities the container needs:\n" +
			"securityContext:\n" +
			"  allowPrivilegeEscalation: false\n" +
			"  runAsNonRoot: true\n" +
			"  capabilities:\n" +
			"    drop: [\"ALL\"]\n" +
			"Enforce with Pod Security Standards (restricted) or Kyverno/OPA policies.",
		refs: []string{
			"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
		},
	},

	// ------------------------------------------------------------------
	// HIGH (highest impact)
	// ------------------------------------------------------------------
	"AEGIS-AWS-001": {
		fix: "Add a server_side_encryption_configuration block:\n" +
			"resource \"aws_s3_bucket_server_side_encryption_configuration\" \"this\" {\n" +
			"  bucket = aws_s3_bucket.this.id\n" +
			"  rule {\n" +
			"    apply_server_side_encryption_by_default {\n" +
			"      sse_algorithm = \"AES256\"  # or \"aws:kms\" with kms_master_key_id\n" +
			"    }\n" +
			"    bucket_key_enabled = true\n" +
			"  }\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
		},
	},
	"AEGIS-AWS-002": {
		fix: "Remove the public ACL grant. Set the bucket ACL to private and rely on bucket\n" +
			"policies for access control:\n" +
			"resource \"aws_s3_bucket_acl\" \"this\" {\n" +
			"  bucket = aws_s3_bucket.this.id\n" +
			"  acl    = \"private\"\n" +
			"}\n" +
			"Then enable all four public-access-block settings (see AEGIS-AWS-003 fix).",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html",
		},
	},
	"AEGIS-AWS-004": {
		fix: "Restrict the ingress CIDR to trusted ranges. Replace `0.0.0.0/0` with your\n" +
			"office/VPN CIDRs, or remove the rule and use SSM Session Manager (no inbound\n" +
			"SSH needed):\n" +
			"ingress {\n" +
			"  from_port   = 22\n" +
			"  to_port     = 22\n" +
			"  protocol    = \"tcp\"\n" +
			"  cidr_blocks = [\"203.0.113.0/24\"]  # your trusted range\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html",
		},
	},
	"AEGIS-AWS-007": {
		fix: "Enable storage encryption on the RDS instance:\n" +
			"resource \"aws_db_instance\" \"this\" {\n" +
			"  # ...\n" +
			"  storage_encrypted = true\n" +
			"  kms_key_id        = aws_kms_key.rds.arn  # optional CMK\n" +
			"}\n" +
			"Note: encryption cannot be enabled on an existing unencrypted instance —\n" +
			"take a snapshot, copy it with encryption, and restore.",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
		},
	},
	"AEGIS-AWS-011": {
		fix: "Set `publicly_accessible = false` and move the database to private subnets:\n" +
			"resource \"aws_db_instance\" \"this\" {\n" +
			"  # ...\n" +
			"  publicly_accessible = false\n" +
			"  db_subnet_group_name = aws_db_subnet_group.private.name\n" +
			"}\n" +
			"Access the database via a bastion host, VPN, or SSM port forwarding — never directly.",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html",
		},
	},
	"AEGIS-AWS-102": {
		fix: "Replace the admin-managed policy attachment with scoped inline or customer-managed\n" +
			"policies (see AEGIS-AWS-006 fix). If break-glass admin access is required, gate it\n" +
			"behind a separate role with MFA condition and CloudTrail alerting:\n" +
			"Condition = { Bool = { \"aws:MultiFactorAuthPresent\" = \"true\" } }",
		refs: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
		},
	},
	"AEGIS-AWS-201": {
		fix: "If the load balancer must be internet-facing, attach a WAFv2 Web ACL and keep\n" +
			"listeners on HTTPS only. Otherwise make it internal:\n" +
			"resource \"aws_lb\" \"this\" {\n" +
			"  internal = true\n" +
			"  # ...\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html",
		},
	},
	"AEGIS-AWS-204": {
		fix: "Enforce IMDSv2 on the instance / launch template:\n" +
			"metadata_options {\n" +
			"  http_endpoint = \"enabled\"\n" +
			"  http_tokens   = \"required\"   # IMDSv2 only\n" +
			"  http_put_response_hop_limit = 1\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
		},
	},
	"AEGIS-AWS-206": {
		fix: "Add the public access block resource (see AEGIS-AWS-003 fix). All four settings\n" +
			"must be true for full protection.",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
	},
	"AEGIS-AWS-307": {
		fix: "Encrypt Lambda environment variables with a customer-managed KMS key:\n" +
			"resource \"aws_lambda_function\" \"this\" {\n" +
			"  # ...\n" +
			"  kms_key_arn = aws_kms_key.lambda.arn\n" +
			"}\n" +
			"Better: don't put secrets in env vars at all — fetch from Secrets Manager at runtime.",
		refs: []string{
			"https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html",
		},
	},
	"AEGIS-AWS-335": {
		fix: "Enable automatic annual rotation on the KMS key:\n" +
			"resource \"aws_kms_key\" \"this\" {\n" +
			"  enable_key_rotation = true\n" +
			"  # ...\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html",
		},
	},
	"AEGIS-AWS-336": {
		fix: "Enable CloudTrail in all regions with log file validation:\n" +
			"resource \"aws_cloudtrail\" \"this\" {\n" +
			"  is_multi_region_trail         = true\n" +
			"  enable_log_file_validation    = true\n" +
			"  kms_key_id                    = aws_kms_key.cloudtrail.arn\n" +
			"  s3_bucket_name                = aws_s3_bucket.trail.id\n" +
			"  include_global_service_events = true\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
		},
	},
	"AEGIS-AWS-338": {
		fix: "Convert the parameter to SecureString with a KMS key:\n" +
			"resource \"aws_ssm_parameter\" \"this\" {\n" +
			"  type   = \"SecureString\"\n" +
			"  key_id = aws_kms_key.ssm.arn\n" +
			"  value  = var.secret_value  # never hardcode\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-parameter-store.html",
		},
	},
	"AEGIS-AWS-339": {
		fix: "Remove the hardcoded credential and rotate it immediately — it is compromised.\n" +
			"Reference a Secrets Manager secret instead:\n" +
			"data \"aws_secretsmanager_secret_version\" \"db\" {\n" +
			"  secret_id = aws_secretsmanager_secret.db.id\n" +
			"}\n" +
			"# then: password = jsondecode(data.aws_secretsmanager_secret_version.db.secret_string)[\"password\"]\n" +
			"If the value was committed to git, purge it from history (BFG/truffleHog) and rotate.",
		refs: []string{
			"https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html",
		},
	},
	"AEGIS-AWS-341": {
		fix: "Encrypt the SNS topic with a customer-managed KMS key:\n" +
			"resource \"aws_sns_topic\" \"this\" {\n" +
			"  kms_master_key_id = aws_kms_key.sns.arn\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html",
		},
	},
	"AEGIS-AWS-342": {
		fix: "Encrypt the SQS queue with a customer-managed KMS key:\n" +
			"resource \"aws_sqs_queue\" \"this\" {\n" +
			"  kms_master_key_id = aws_kms_key.sqs.arn\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html",
		},
	},
	"AEGIS-AWS-333": {
		fix: "Move the inline admin policy to a scoped customer-managed policy (see\n" +
			"AEGIS-AWS-006 fix). Inline policies on identities are hard to audit — prefer\n" +
			"managed policies attached to groups/roles.",
		refs: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege",
		},
	},
	"AEGIS-AWS-305": {
		fix: "Make the EKS API endpoint private:\n" +
			"resource \"aws_eks_cluster\" \"this\" {\n" +
			"  vpc_config {\n" +
			"    endpoint_private_access = true\n" +
			"    endpoint_public_access  = false\n" +
			"  }\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html",
		},
	},
	"AEGIS-AWS-325": {
		fix: "Redirect HTTP to HTTPS on the CloudFront distribution:\n" +
			"resource \"aws_cloudfront_distribution\" \"this\" {\n" +
			"  # ...\n" +
			"  default_cache_behavior {\n" +
			"    viewer_protocol_policy = \"redirect-to-https\"\n" +
			"    # ...\n" +
			"  }\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
		},
	},
	"AEGIS-AWS-552": {
		fix: "Rotate IAM access keys every 90 days or less. Prefer short-lived credentials:\n" +
			"federate via IAM Identity Center / SSO, or use instance profiles and ECS task roles\n" +
			"instead of long-lived keys. Audit with IAM Access Analyzer unused-access findings.",
		refs: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
		},
	},
	"AEGIS-AWS-553": {
		fix: "Replace `NotAction` + `Allow` with explicit `Action` lists. NotAction inverts\n" +
			"matching and is easy to misread — enumerate exactly what the identity may do\n" +
			"(see AEGIS-AWS-006 fix).",
		refs: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html",
		},
	},
	"AEGIS-AWS-561": {
		fix: "Set a deletion window of 7–30 days so accidental key deletion is recoverable:\n" +
			"resource \"aws_kms_key\" \"this\" {\n" +
			"  deletion_window_in_days = 30\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html",
		},
	},
	"AEGIS-AWS-567": {
		fix: "Enable Security Hub with the CIS and FSBP standards:\n" +
			"resource \"aws_securityhub_account\" \"this\" {}\n" +
			"resource \"aws_securityhub_standards_subscription\" \"cis\" {\n" +
			"  standards_arn = \"arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0\"\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-settingup.html",
		},
	},
	"AEGIS-AWS-568": {
		fix: "Encrypt CloudTrail logs with a KMS key (see AEGIS-AWS-336 fix):\n" +
			"resource \"aws_cloudtrail\" \"this\" {\n" +
			"  kms_key_id = aws_kms_key.cloudtrail.arn\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
		},
	},
	// ------------------------------------------------------------------
	// Aurora coverage gaps (AEGIS-AWS-631..636)
	// ------------------------------------------------------------------
	"AEGIS-AWS-631": {
		fix: "Export audit logs from the cluster to CloudWatch Logs:\n" +
			"resource \"aws_rds_cluster\" \"this\" {\n" +
			"  enabled_cloudwatch_logs_exports = [\"audit\", \"error\"]\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_LogAccess.html",
		},
	},
	"AEGIS-AWS-632": {
		fix: "Enable backtracking on the Aurora MySQL cluster (up to 259200 seconds):\n" +
			"resource \"aws_rds_cluster\" \"this\" {\n" +
			"  engine           = \"aurora-mysql\"\n" +
			"  backtrack_window = 86400\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Managing.Backtrack.html",
		},
	},
	"AEGIS-AWS-633": {
		fix: "Copy cluster tags to snapshots so cost and ownership metadata survive restores:\n" +
			"resource \"aws_rds_cluster\" \"this\" {\n" +
			"  copy_tags_to_snapshot = true\n" +
			"}",
		refs: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster",
		},
	},
	"AEGIS-AWS-634": {
		fix: "Encrypt the cluster with a customer-managed KMS key (see AEGIS-AWS-359 fix):\n" +
			"resource \"aws_rds_cluster\" \"this\" {\n" +
			"  storage_encrypted = true\n" +
			"  kms_key_id        = aws_kms_key.rds.arn\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Overview.Encryption.html",
		},
	},
	"AEGIS-AWS-635": {
		fix: "Enable Performance Insights on the cluster:\n" +
			"resource \"aws_rds_cluster\" \"this\" {\n" +
			"  performance_insights_enabled = true\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.html",
		},
	},
	"AEGIS-AWS-636": {
		fix: "Enable enhanced monitoring (1-60 second granularity; requires a monitoring role):\n" +
			"resource \"aws_rds_cluster\" \"this\" {\n" +
			"  monitoring_interval          = 60\n" +
			"  monitoring_role_arn          = aws_iam_role.rds_enhanced_monitoring.arn\n" +
			"}",
		refs: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.OS.html",
		},
	},

	// ------------------------------------------------------------------
	// AZURE MSSQL (AEGIS-AZURE-101..108)
	// ------------------------------------------------------------------
	"AEGIS-AZURE-101": {
		fix: "Attach an extended auditing policy to the server:\n" +
			"resource \"azurerm_mssql_server_extended_auditing_policy\" \"audit\" {\n" +
			"  server_id                  = azurerm_mssql_server.db.id\n" +
			"  storage_endpoint           = azurerm_storage_account.audit.primary_blob_endpoint\n" +
			"  storage_account_access_key = azurerm_storage_account.audit.primary_access_key\n" +
			"  retention_in_days          = 90\n" +
			"}",
		refs: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_extended_auditing_policy",
		},
	},
	"AEGIS-AZURE-102": {
		fix: "Raise the audit log retention on the extended auditing policy:\n" +
			"resource \"azurerm_mssql_server_extended_auditing_policy\" \"audit\" {\n" +
			"  retention_in_days = 90\n" +
			"}",
		refs: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_extended_auditing_policy",
		},
	},
	"AEGIS-AZURE-103": {
		fix: "Enable the security alert policy and clear disabled_alerts so all\n" +
			"threat types are detected:\n" +
			"resource \"azurerm_mssql_server_security_alert_policy\" \"pol\" {\n" +
			"  resource_group_name  = azurerm_resource_group.rg.name\n" +
			"  server_name          = azurerm_mssql_server.db.name\n" +
			"  state                = \"Enabled\"\n" +
			"  disabled_alerts      = []\n" +
			"  email_account_admins = true\n" +
			"}",
		refs: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy",
		},
	},
	"AEGIS-AZURE-104": {
		fix: "Notify account admins on security alerts:\n" +
			"resource \"azurerm_mssql_server_security_alert_policy\" \"pol\" {\n" +
			"  email_account_admins = true\n" +
			"}",
		refs: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_security_alert_policy",
		},
	},
	"AEGIS-AZURE-105": {
		fix: "Enforce TLS 1.2 on the server:\n" +
			"resource \"azurerm_mssql_server\" \"db\" {\n" +
			"  minimum_tls_version = \"1.2\"\n" +
			"}",
		refs: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server",
		},
	},
	"AEGIS-AZURE-106": {
		fix: "Disable public network access and front the server with a private endpoint:\n" +
			"resource \"azurerm_mssql_server\" \"db\" {\n" +
			"  public_network_access_enabled = false\n" +
			"}",
		refs: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server",
		},
	},
	"AEGIS-AZURE-107": {
		fix: "Add an Azure AD administrator to the server:\n" +
			"resource \"azurerm_mssql_server_azuread_administrator\" \"ad\" {\n" +
			"  server_id                   = azurerm_mssql_server.db.id\n" +
			"  login_username              = \"sql-admin\"\n" +
			"  object_id                   = data.azuread_user.admin.object_id\n" +
			"  tenant_id                   = data.azurerm_client_config.current.tenant_id\n" +
			"  azuread_authentication_only = true\n" +
			"}",
		refs: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server_azuread_administrator",
		},
	},
	"AEGIS-AZURE-108": {
		fix: "Create a private endpoint for the SQL server subresource:\n" +
			"resource \"azurerm_private_endpoint\" \"sql\" {\n" +
			"  subnet_id = azurerm_subnet.db.id\n" +
			"  private_service_connection {\n" +
			"    name                           = \"sql-privatelink\"\n" +
			"    private_connection_resource_id = azurerm_mssql_server.db.id\n" +
			"    subresource_names              = [\"sqlServer\"]\n" +
			"    is_manual_connection           = false\n" +
			"  }\n" +
			"}",
		refs: []string{
			"https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/private_endpoint",
		},
	},
}
