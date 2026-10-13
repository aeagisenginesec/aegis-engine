package cloudformation

// cfnToTF maps CloudFormation resource types to Terraform resource types.
// Only AWS types are mapped; everything else is skipped with a diagnostic.
var cfnToTF = map[string]string{
	// S3
	"AWS::S3::Bucket":            "aws_s3_bucket",
	"AWS::S3::BucketPolicy":      "aws_s3_bucket_policy",
	"AWS::S3::AccessPoint":       "aws_s3_access_point",
	"AWS::S3::PublicAccessBlock": "aws_s3_bucket_public_access_block",

	// EC2
	"AWS::EC2::Instance":             "aws_instance",
	"AWS::EC2::Volume":               "aws_ebs_volume",
	"AWS::EC2::Snapshot":             "aws_ebs_snapshot",
	"AWS::EC2::SecurityGroup":        "aws_security_group",
	"AWS::EC2::SecurityGroupIngress": "aws_security_group_rule",
	"AWS::EC2::SecurityGroupEgress":  "aws_security_group_rule",
	"AWS::EC2::VPC":                  "aws_vpc",
	"AWS::EC2::Subnet":               "aws_subnet",
	"AWS::EC2::RouteTable":           "aws_route_table",
	"AWS::EC2::Route":                "aws_route",
	"AWS::EC2::InternetGateway":      "aws_internet_gateway",
	"AWS::EC2::NatGateway":           "aws_nat_gateway",
	"AWS::EC2::EIP":                  "aws_eip",
	"AWS::EC2::NetworkAcl":           "aws_network_acl",
	"AWS::EC2::VPCEndpoint":          "aws_vpc_endpoint",
	"AWS::EC2::FlowLog":              "aws_flow_log",
	"AWS::EC2::LaunchTemplate":       "aws_launch_template",
	"AWS::EC2::KeyPair":              "aws_key_pair",
	"AWS::EC2::PlacementGroup":       "aws_placement_group",

	// IAM
	"AWS::IAM::Role":            "aws_iam_role",
	"AWS::IAM::Policy":          "aws_iam_policy",
	"AWS::IAM::ManagedPolicy":   "aws_iam_policy",
	"AWS::IAM::User":            "aws_iam_user",
	"AWS::IAM::Group":           "aws_iam_group",
	"AWS::IAM::InstanceProfile": "aws_iam_instance_profile",
	"AWS::IAM::AccessKey":       "aws_iam_access_key",
	"AWS::IAM::OIDCProvider":    "aws_iam_openid_connect_provider",
	"AWS::IAM::SAMLProvider":    "aws_iam_saml_provider",

	// RDS / databases
	"AWS::RDS::DBInstance":               "aws_db_instance",
	"AWS::RDS::DBCluster":                "aws_rds_cluster",
	"AWS::RDS::DBSubnetGroup":            "aws_db_subnet_group",
	"AWS::RDS::DBParameterGroup":         "aws_db_parameter_group",
	"AWS::RDS::OptionGroup":              "aws_db_option_group",
	"AWS::Redshift::Cluster":             "aws_redshift_cluster",
	"AWS::ElastiCache::CacheCluster":     "aws_elasticache_cluster",
	"AWS::ElastiCache::ReplicationGroup": "aws_elasticache_replication_group",
	"AWS::DynamoDB::Table":               "aws_dynamodb_table",
	"AWS::Neptune::DBCluster":            "aws_neptune_cluster",
	"AWS::DocDB::DBCluster":              "aws_docdb_cluster",

	// Lambda / serverless
	"AWS::Lambda::Function":     "aws_lambda_function",
	"AWS::Lambda::LayerVersion": "aws_lambda_layer_version",
	"AWS::Lambda::Url":          "aws_lambda_function_url",
	"AWS::Serverless::Function": "aws_lambda_function",
	"AWS::Serverless::Api":      "aws_api_gateway_rest_api",

	// ECS / EKS
	"AWS::ECS::Cluster":        "aws_ecs_cluster",
	"AWS::ECS::Service":        "aws_ecs_service",
	"AWS::ECS::TaskDefinition": "aws_ecs_task_definition",
	"AWS::EKS::Cluster":        "aws_eks_cluster",
	"AWS::EKS::Nodegroup":      "aws_eks_node_group",

	// Load balancing
	"AWS::ElasticLoadBalancingV2::LoadBalancer": "aws_lb",
	"AWS::ElasticLoadBalancingV2::Listener":     "aws_lb_listener",
	"AWS::ElasticLoadBalancingV2::TargetGroup":  "aws_lb_target_group",
	"AWS::ElasticLoadBalancing::LoadBalancer":   "aws_elb",

	// Networking / DNS / CDN
	"AWS::Route53::HostedZone":      "aws_route53_zone",
	"AWS::Route53::RecordSet":       "aws_route53_record",
	"AWS::CloudFront::Distribution": "aws_cloudfront_distribution",
	"AWS::ApiGateway::RestApi":      "aws_api_gateway_rest_api",
	"AWS::ApiGateway::Stage":        "aws_api_gateway_stage",
	"AWS::ApiGatewayV2::Api":        "aws_apigatewayv2_api",
	"AWS::ApiGatewayV2::Stage":      "aws_apigatewayv2_stage",

	// Security / KMS / secrets
	"AWS::KMS::Key":                      "aws_kms_key",
	"AWS::KMS::Alias":                    "aws_kms_alias",
	"AWS::SecretsManager::Secret":        "aws_secretsmanager_secret",
	"AWS::SSM::Parameter":                "aws_ssm_parameter",
	"AWS::WAFv2::WebACL":                 "aws_wafv2_web_acl",
	"AWS::WAFv2::WebACLAssociation":      "aws_wafv2_web_acl_association",
	"AWS::Shield::Protection":            "aws_shield_protection",
	"AWS::GuardDuty::Detector":           "aws_guardduty_detector",
	"AWS::SecurityHub::Hub":              "aws_securityhub_account",
	"AWS::Macie::Session":                "aws_macie2_account",
	"AWS::Config::ConfigRule":            "aws_config_config_rule",
	"AWS::Config::ConfigurationRecorder": "aws_config_configuration_recorder",

	// Logging / monitoring
	"AWS::CloudTrail::Trail":     "aws_cloudtrail",
	"AWS::Logs::LogGroup":        "aws_cloudwatch_log_group",
	"AWS::Logs::MetricFilter":    "aws_cloudwatch_log_metric_filter",
	"AWS::CloudWatch::Alarm":     "aws_cloudwatch_metric_alarm",
	"AWS::CloudWatch::Dashboard": "aws_cloudwatch_dashboard",

	// Messaging
	"AWS::SNS::Topic":        "aws_sns_topic",
	"AWS::SNS::Subscription": "aws_sns_topic_subscription",
	"AWS::SQS::Queue":        "aws_sqs_queue",

	// Storage
	"AWS::EFS::FileSystem":     "aws_efs_file_system",
	"AWS::EFS::MountTarget":    "aws_efs_mount_target",
	"AWS::Backup::BackupVault": "aws_backup_vault",
	"AWS::Backup::BackupPlan":  "aws_backup_plan",

	// Certificates
	"AWS::CertificateManager::Certificate": "aws_acm_certificate",

	// Search / analytics
	"AWS::OpenSearchService::Domain":       "aws_opensearch_domain",
	"AWS::Elasticsearch::Domain":           "aws_elasticsearch_domain",
	"AWS::Kinesis::Stream":                 "aws_kinesis_stream",
	"AWS::KinesisFirehose::DeliveryStream": "aws_kinesis_firehose_delivery_stream",
	"AWS::MSK::Cluster":                    "aws_msk_cluster",
	"AWS::Athena::WorkGroup":               "aws_athena_workgroup",
	"AWS::Glue::Job":                       "aws_glue_job",
	"AWS::EMR::Cluster":                    "aws_emr_cluster",

	// SageMaker / AI
	"AWS::SageMaker::NotebookInstance": "aws_sagemaker_notebook_instance",
	"AWS::SageMaker::Domain":           "aws_sagemaker_domain",
	"AWS::Bedrock::Guardrail":          "aws_bedrock_guardrail",

	// Eventing / workflow
	"AWS::Events::Rule":                "aws_cloudwatch_event_rule",
	"AWS::StepFunctions::StateMachine": "aws_sfn_state_machine",
	"AWS::AppSync::GraphQLApi":         "aws_appsync_graphql_api",

	// API / containers registry
	"AWS::ECR::Repository": "aws_ecr_repository",

	// Auto scaling
	"AWS::AutoScaling::AutoScalingGroup":          "aws_autoscaling_group",
	"AWS::AutoScaling::LaunchConfiguration":       "aws_launch_configuration",
	"AWS::ApplicationAutoScaling::ScalableTarget": "aws_appautoscaling_target",
}

// cfnTypeToTF maps a CloudFormation type to its Terraform equivalent.
func cfnTypeToTF(cfnType string) (string, bool) {
	tf, ok := cfnToTF[cfnType]
	return tf, ok
}
