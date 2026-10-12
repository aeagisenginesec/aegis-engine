package aws

// Property test for the unknown-value contract (see helpers.go and the
// package doc): a present-but-unresolved attribute (Value.Known == false)
// means "cannot decide" and must NEVER produce a finding from any AWS rule.
// Absent attributes are fail-closed per provider defaults (see
// absentInsecureDefault); unknown attributes are not.
//
// For every rule and every resource type it applies to, a resource whose
// every attribute is present-but-unknown must yield zero findings — from
// Check and, for cross-resource rules, from CheckAll.

import (
	"testing"

	"aegis/internal/ir"
)

// unknownAttrNames is every attribute name any AWS rule reads, harvested
// from the getBool/getString/getBlocks/block* call sites.
var unknownAttrNames = []string{
	"acceptance_required",
	"access_log_settings",
	"access_logs",
	"access_string",
	"acl",
	"advanced_security_options",
	"allow_external_principals",
	"allow_unauthenticated_identities",
	"apply_on",
	"artifact_store",
	"artifacts",
	"associate_public_ip_address",
	"assume_role_policy",
	"at_rest_encryption_enabled",
	"auth_mode",
	"auth_token",
	"authentication",
	"authentication_type",
	"authorization",
	"authorization_type",
	"auto_accept",
	"auto_minor_version_upgrade",
	"automatic_failover_enabled",
	"automatically_after_days",
	"backtrack_window",
	"backup_retention_period",
	"block_device_mappings",
	"bucket",
	"cidr_block",
	"client_broker",
	"cluster_config",
	"cluster_endpoint_encryption_type",
	"cluster_subnet_group_name",
	"code_signing_config",
	"configuration",
	"container_definitions",
	"copy_tags_to_snapshot",
	"cors_configuration",
	"data_catalog_encryption_settings",
	"dead_letter_config",
	"default",
	"default_action",
	"delete_protection",
	"deletion_protection",
	"deletion_protection_enabled",
	"deletion_window_in_days",
	"deployment_circuit_breaker",
	"description",
	"direct_internet_access",
	"domain_endpoint_options",
	"drop_invalid_header_fields",
	"ebs_block_device",
	"ebs_optimized",
	"egress",
	"enable",
	"enable_cloudwatch_logs_exports",
	"enable_default_internet_access",
	"enable_deletion_protection",
	"enable_key_rotation",
	"enable_log_file_validation",
	"enabled",
	"enabled_cloudwatch_logs_exports",
	"enabled_cloudwatch_logs_log_exports",
	"enabled_cluster_log_types",
	"encrypted",
	"encryption_config",
	"encryption_configuration",
	"encryption_info",
	"encryption_options",
	"encryption_type",
	"endpoint_type",
	"enforce_workgroup_configuration",
	"engine",
	"enhanced_vpc_routing",
	"environment",
	"force_destroy",
	"http_tokens",
	"iam_database_authentication_enabled",
	"image_scanning_configuration",
	"image_tag_mutability",
	"include_global_service_events",
	"ingress",
	"inline_policy",
	"instance_metadata_service_configuration",
	"internal",
	"is_multi_region_trail",
	"kms_key",
	"kms_key_arn",
	"kms_key_id",
	"kms_master_key_id",
	"lifecycle_rule",
	"listener",
	"log_config",
	"log_publishing_options",
	"log_type",
	"logging",
	"logging_config",
	"logging_configuration",
	"logging_info",
	"logging_role",
	"logs",
	"logs_config",
	"map_public_ip_on_launch",
	"master_username",
	"max_session_duration",
	"metadata_options",
	"mfa_configuration",
	"mfa_delete",
	"minimum_password_length",
	"monitoring",
	"monitoring_interval",
	"multi_az",
	"multi_az_enabled",
	"name",
	"network_configuration",
	"network_mode",
	"operations",
	"origin",
	"password_policy",
	"password_reuse_prevention",
	"performance_insights_enabled",
	"encrypt_at_rest",
	"node_to_node_encryption",
	"server_side_encryption",
	"point_in_time_recovery",
	"performance_insights_kms_key_id",
	"pgp_key",
	"policy",
	"port",
	"principal",
	"protocol",
	"publicly_accessible",
	"recording_group",
	"remote_access",
	"replication_configuration",
	"require_tls",
	"reserved_concurrent_executions",
	"resource_arn",
	"restrict_public_buckets",
	"restrictions",
	"retention_in_days",
	"root_volume_encryption_enabled",
	"rotation_rules",
	"rule",
	"rule_action",
	"runtime",
	"s3_bucket_name",
	"scope",
	"secret_string",
	"security_configuration",
	"security_policy",
	"security_policy_name",
	"sensitive",
	"server_side_encryption_configuration",
	"setting",
	"snap_start",
	"snapshot_options",
	"snapshot_retention_limit",
	"sqs_managed_sse_enabled",
	"ssl_mode",
	"ssl_policy",
	"status",
	"storage_encrypted",
	"subnet_id",
	"tags",
	"tls_enabled",
	"tracing_config",
	"tracing_configuration",
	"transit_encryption_enabled",
	"type",
	"upstream",
	"use_aws_owned_key",
	"user_pool_add_ons",
	"user_volume_encryption_enabled",
	"value",
	"versioning",
	"versioning_configuration",
	"viewer_certificate",
	"viewer_protocol_policy",
	"visible_to_all_users",
	"vpc_config",
	"vpc_id",
	"vpc_options",
	"web_acl_id",
	"xray_enabled",
}

// unknownAttrTypes is every resource type any AWS rule AppliesTo, harvested
// from AppliesTo implementations.
var unknownAttrTypes = []string{
	"aws_alb",
	"aws_alb_listener",
	"aws_api_gateway_api_key",
	"aws_api_gateway_domain_name",
	"aws_api_gateway_method",
	"aws_api_gateway_stage",
	"aws_apigatewayv2_api",
	"aws_apigatewayv2_route",
	"aws_apigatewayv2_stage",
	"aws_apprunner_service",
	"aws_appstream_fleet",
	"aws_appsync_graphql_api",
	"aws_athena_workgroup",
	"aws_backup_vault",
	"aws_cloudfront_distribution",
	"aws_cloudtrail",
	"aws_cloudwatch_event_permission",
	"aws_cloudwatch_log_group",
	"aws_codeartifact_repository",
	"aws_codebuild_project",
	"aws_codepipeline",
	"aws_codepipeline_webhook",
	"aws_cognito_identity_pool",
	"aws_cognito_user_pool",
	"aws_config_configuration_recorder",
	"aws_dax_cluster",
	"aws_db_instance",
	"aws_db_proxy",
	"aws_default_security_group",
	"aws_default_subnet",
	"aws_default_vpc",
	"aws_detective_graph",
	"aws_dms_endpoint",
	"aws_dms_replication_instance",
	"aws_docdb_cluster",
	"aws_dynamodb_table",
	"aws_ebs_encryption_by_default",
	"aws_ebs_volume",
	"aws_ec2_transit_gateway_route_table_propagation",
	"aws_ecr_repository",
	"aws_ecr_repository_policy",
	"aws_ecs_cluster",
	"aws_ecs_service",
	"aws_ecs_task_definition",
	"aws_efs_file_system",
	"aws_efs_file_system_policy",
	"aws_eks_cluster",
	"aws_eks_node_group",
	"aws_elastic_beanstalk_environment",
	"aws_elasticache_replication_group",
	"aws_elasticache_user",
	"aws_elasticsearch_domain",
	"aws_elb",
	"aws_emr_cluster",
	"aws_emr_security_configuration",
	"aws_flow_log",
	"aws_fsx_lustre_file_system",
	"aws_fsx_ontap_file_system",
	"aws_fsx_openzfs_file_system",
	"aws_fsx_windows_file_system",
	"aws_glue_data_catalog_encryption_settings",
	"aws_glue_job",
	"aws_guardduty_detector",
	"aws_iam_access_key",
	"aws_iam_account_password_policy",
	"aws_iam_group_policy",
	"aws_iam_policy",
	"aws_iam_role",
	"aws_iam_role_policy",
	"aws_iam_user_policy",
	"aws_instance",
	"aws_iot_policy",
	"aws_kinesis_firehose_delivery_stream",
	"aws_kinesis_stream",
	"aws_kms_grant",
	"aws_kms_key",
	"aws_lambda_function",
	"aws_lambda_function_url",
	"aws_lambda_permission",
	"aws_launch_configuration",
	"aws_launch_template",
	"aws_lb",
	"aws_lb_listener",
	"aws_lb_target_group",
	"aws_memorydb_cluster",
	"aws_mq_broker",
	"aws_mq_configuration",
	"aws_msk_cluster",
	"aws_neptune_cluster",
	"aws_network_acl",
	"aws_network_acl_rule",
	"aws_networkfirewall_firewall",
	"aws_opensearch_domain",
	"aws_organizations_organization",
	"aws_ram_resource_share",
	"aws_rds_cluster",
	"aws_redshift_cluster",
	"aws_redshiftserverless_namespace",
	"aws_redshiftserverless_workgroup",
	"aws_s3_account_public_access_block",
	"aws_s3_bucket",
	"aws_s3_bucket_acl",
	"aws_s3_bucket_inventory",
	"aws_s3_bucket_lifecycle_configuration",
	"aws_s3_bucket_logging",
	"aws_s3_bucket_notification",
	"aws_s3_bucket_object_lock_configuration",
	"aws_s3_bucket_policy",
	"aws_s3_bucket_public_access_block",
	"aws_s3_bucket_replication_configuration",
	"aws_s3_bucket_server_side_encryption_configuration",
	"aws_s3_bucket_versioning",
	"aws_s3control_access_point_policy",
	"aws_sagemaker_domain",
	"aws_sagemaker_endpoint_configuration",
	"aws_sagemaker_notebook_instance",
	"aws_secretsmanager_secret",
	"aws_secretsmanager_secret_rotation",
	"aws_secretsmanager_secret_version",
	"aws_security_group",
	"aws_security_group_rule",
	"aws_securityhub_account",
	"aws_sfn_state_machine",
	"aws_sns_topic",
	"aws_sns_topic_policy",
	"aws_sns_topic_subscription",
	"aws_sqs_queue",
	"aws_sqs_queue_policy",
	"aws_ssm_parameter",
	"aws_ssoadmin_permission_set_inline_policy",
	"aws_subnet",
	"aws_timestreamwrite_database",
	"aws_transfer_server",
	"aws_vpc",
	"aws_vpc_endpoint",
	"aws_vpc_endpoint_service",
	"aws_vpc_peering_connection",
	"aws_vpc_security_group_egress_rule",
	"aws_vpc_security_group_ingress_rule",
	"aws_wafv2_web_acl",
	"aws_wafv2_web_acl_association",
	"aws_wafv2_web_acl_logging_configuration",
	"aws_workspaces_workspace",
	"terraform_locals",
	"terraform_output",
	"terraform_variable",
}

func allUnknownResource(typ string) ir.Resource {
	attrs := make(map[string]ir.Value, len(unknownAttrNames))
	for _, name := range unknownAttrNames {
		attrs[name] = ir.Value{Known: false, Span: ir.Span{File: "t.tf", StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 10}, Ref: "var.unknown"}
	}
	return ir.Resource{
		Type: typ, Name: "x", Provider: "aws",
		Attributes: attrs,
		Span:       ir.Span{File: "t.tf", StartLine: 1, StartCol: 1, EndLine: 5, EndCol: 1},
	}
}

// structuralRules fire on the mere existence of the resource (the resource
// type itself is the misconfiguration: a deprecated resource, a default
// VPC/subnet in use, TGW propagation). They read no attribute values, so
// all-unknown attributes cannot suppress them — and must not.
var structuralRules = map[string]bool{
	"AEGIS-AWS-309": true, // deprecated launch configuration in use
	"AEGIS-AWS-396": true, // default VPC in use
	"AEGIS-AWS-400": true, // default subnet in use
	"AEGIS-AWS-556": true, // TGW route table propagation enabled
}

func TestUnknownNeverFires_Check(t *testing.T) {
	for _, rule := range Rules() {
		if structuralRules[rule.ID()] {
			continue
		}
		for _, typ := range unknownAttrTypes {
			if !rule.AppliesTo(typ) {
				continue
			}
			r := allUnknownResource(typ)
			fs := rule.Check(r)
			if len(fs) != 0 {
				t.Errorf("%s on %s with all-unknown attributes: got %d findings, want 0 (first: %q)",
					rule.ID(), typ, len(fs), fs[0].Title)
			}
		}
	}
}

func TestUnknownNeverFires_CheckAll(t *testing.T) {
	// Every known resource type is present with all-unknown attributes, so
	// companion resources (public access blocks, flow logs, bucket policies,
	// logging/notification/inventory configs, WAF associations, ...) exist
	// but their links to parents are unresolvable. Any "companion missing"
	// finding is therefore undecidable and must not fire.
	var resources []ir.Resource
	for _, typ := range unknownAttrTypes {
		resources = append(resources, allUnknownResource(typ))
	}
	for _, rule := range Rules() {
		cr, ok := rule.(ir.CrossResourceRule)
		if !ok {
			continue
		}
		fs := cr.CheckAll(resources)
		if len(fs) != 0 {
			t.Errorf("%s CheckAll with all-unknown resources: got %d findings, want 0 (first: %q)",
				rule.ID(), len(fs), fs[0].Title)
		}
	}
}
