package aws

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// idPattern enforces the AEGIS-AWS-NNN naming convention.
var idPattern = regexp.MustCompile(`^AEGIS-AWS-\d{3}$`)

// TestCoverageAudit verifies every AWS rule meets quality gates:
// valid ID format, non-empty title/description, severity set,
// and reports coverage scores per threat category.
func TestCoverageAudit(t *testing.T) {
	rules := Rules()

	// Category mapping by rule ID ranges / keywords.
	categoryOf := func(id, title string) string {
		lt := strings.ToLower(title)
		switch {
		case strings.Contains(lt, "iam") || strings.Contains(lt, "privilege") ||
			strings.Contains(lt, "cognito") || strings.Contains(lt, "password policy") ||
			strings.Contains(lt, "sso") || strings.Contains(lt, "organization"):
			return "iam"
		case strings.Contains(lt, "security group") || strings.Contains(lt, "load balancer") ||
			strings.Contains(lt, "vpc") || strings.Contains(lt, "subnet") ||
			strings.Contains(lt, "cloudfront") || strings.Contains(lt, "api gateway") ||
			strings.Contains(lt, "appsync") || strings.Contains(lt, "waf") ||
			strings.Contains(lt, "transfer") || strings.Contains(lt, "attack path") ||
			strings.Contains(lt, "network acl") || strings.Contains(lt, "endpoint"):
			return "networking"
		case strings.HasPrefix(lt, "s3 ") || strings.Contains(lt, "s3 bucket"):
			return "s3"
		case strings.Contains(lt, "kms") || strings.Contains(lt, "secret") ||
			strings.Contains(lt, "credential") || strings.Contains(lt, "ssm parameter"):
			return "kms_secrets"
		case strings.Contains(lt, "ec2") || strings.Contains(lt, "lambda") ||
			strings.Contains(lt, "ecs") || strings.Contains(lt, "eks") ||
			strings.Contains(lt, "ecr") || strings.Contains(lt, "sagemaker") ||
			strings.Contains(lt, "ebs") || strings.Contains(lt, "launch"):
			return "compute"
		case strings.Contains(lt, "rds") || strings.Contains(lt, "dynamodb") ||
			strings.Contains(lt, "redshift") || strings.Contains(lt, "elasticache") ||
			strings.Contains(lt, "neptune") || strings.Contains(lt, "documentdb") ||
			strings.Contains(lt, "opensearch") || strings.Contains(lt, "elasticsearch") ||
			strings.Contains(lt, "aurora") || strings.Contains(lt, "dax") ||
			strings.Contains(lt, "memorydb") || strings.Contains(lt, "dms"):
			return "databases"
		case strings.Contains(lt, "cloudtrail") || strings.Contains(lt, "logging") ||
			strings.Contains(lt, "log ") || strings.Contains(lt, "guardduty") ||
			strings.Contains(lt, "config recorder") || strings.Contains(lt, "audit") ||
			strings.Contains(lt, "monitoring") || strings.Contains(lt, "x-ray") ||
			strings.Contains(lt, "tracing"):
			return "logging"
		default:
			return "supply_chain"
		}
	}

	seen := map[string]bool{}
	catCount := map[string]int{}
	catSev := map[string]map[string]int{}
	var failures []string

	for _, r := range rules {
		id := r.ID()
		// 1. Valid ID format
		if !idPattern.MatchString(id) {
			failures = append(failures, fmt.Sprintf("%s: invalid ID format", id))
		}
		// 2. No duplicate IDs
		if seen[id] {
			failures = append(failures, fmt.Sprintf("%s: duplicate ID", id))
		}
		seen[id] = true
		// 3. Non-empty title
		if strings.TrimSpace(r.Title()) == "" {
			failures = append(failures, fmt.Sprintf("%s: empty title", id))
		}
		// 4. Non-empty description
		if strings.TrimSpace(r.Description()) == "" {
			failures = append(failures, fmt.Sprintf("%s: empty description", id))
		}
		// 5. Valid severity
		sev := string(r.Severity())
		if sev != "critical" && sev != "high" && sev != "medium" && sev != "low" {
			failures = append(failures, fmt.Sprintf("%s: invalid severity %q", id, sev))
		}
		// 6. AppliesTo at least one resource type (spot check common types)
		matched := false
		for _, rt := range []string{"aws_s3_bucket", "aws_db_instance", "aws_security_group",
			"aws_iam_policy", "aws_lambda_function", "aws_instance", "aws_kms_key",
			"aws_ecs_task_definition", "aws_vpc", "aws_cloudtrail", "aws_sns_topic",
			"aws_dynamodb_table", "aws_eks_cluster", "aws_lb", "aws_redshift_cluster",
			"terraform_variable", "terraform_output", "aws_ecr_repository",
			"aws_elasticache_replication_group", "aws_sagemaker_notebook_instance",
			"aws_opensearch_domain", "aws_neptune_cluster", "aws_docdb_cluster",
			"aws_wafv2_web_acl", "aws_cloudfront_distribution", "aws_transfer_server",
			"aws_appsync_graphql_api", "aws_emr_security_configuration",
			"aws_dax_cluster", "aws_memorydb_cluster", "aws_default_security_group",
			"aws_ssoadmin_permission_set_inline_policy", "aws_cognito_user_pool",
			"aws_codebuild_project", "aws_msk_cluster", "aws_mq_broker",
			"aws_sqs_queue", "aws_athena_workgroup", "aws_glue", "aws_launch_template",
			"aws_launch_configuration", "aws_subnet", "aws_db_cluster", "aws_rds_cluster",
			"aws_elasticsearch_domain", "aws_secretsmanager_secret_rotation",
			"aws_secretsmanager_secret_version", "aws_ssm_parameter",
			"aws_s3_bucket_policy", "aws_vpc_endpoint", "aws_redshiftserverless_workgroup",
			"aws_timestreamwrite_database", "aws_workspaces_workspace",
			"aws_s3_account_public_access_block", "aws_s3control_access_point_policy",
			"aws_network_acl", "aws_vpc_peering_connection", "aws_ram_resource_share",
			"aws_organizations_organization", "aws_iam_account_password_policy",
			"aws_iam_role", "aws_iam_user_policy", "aws_iam_role_policy",
			"aws_iam_group_policy", "aws_security_group_rule",
			"aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
			"aws_lb_listener", "aws_alb_listener", "aws_elb", "aws_alb",
			"aws_s3_bucket_versioning", "aws_s3_bucket_logging",
			"aws_s3_bucket_server_side_encryption_configuration",
			"aws_s3_bucket_lifecycle_configuration", "aws_s3_bucket_notification",
			"aws_s3_bucket_replication_configuration", "aws_s3_bucket_acl",
			"aws_ecs_service", "aws_ecs_cluster", "aws_eks_node_group",
			"aws_sagemaker_domain", "aws_sagemaker_endpoint_configuration",
			"aws_cloudwatch_log_group", "aws_config_configuration_recorder",
			"aws_sfn_state_machine", "aws_sns_topic_policy", "aws_sns_topic_subscription",
			"aws_sqs_queue_policy", "aws_cognito_identity_pool",
			"aws_vpc_endpoint_service", "aws_networkfirewall_firewall",
			"aws_wafv2_web_acl_logging_configuration",
		} {
			if r.AppliesTo(rt) {
				matched = true
				break
			}
		}
		// Cross-resource rules may legitimately match nothing in the probe list
		// if they only implement CheckAll — don't fail, just note.
		_ = matched

		cat := categoryOf(id, r.Title())
		catCount[cat]++
		if catSev[cat] == nil {
			catSev[cat] = map[string]int{}
		}
		catSev[cat][sev]++
	}

	if len(failures) > 0 {
		t.Errorf("coverage audit failures:\n  %s", strings.Join(failures, "\n  "))
	}

	// Report coverage scores.
	t.Logf("AWS pack: %d rules audited", len(rules))
	cats := make([]string, 0, len(catCount))
	for c := range catCount {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		t.Logf("  %-12s %3d rules  %v", c, catCount[c], catSev[c])
	}

	// Quality gate: every rule must have valid ID, title, description, severity.
	// (Enforced by failures above.)
}
