// typemap.go — Pulumi type tokens to canonical (Terraform-style) resource types.
//
// Pulumi type tokens have the form <package>:<module>:<Type>, e.g.
// aws:s3:Bucket, azure-native:storage:StorageAccount, gcp:storage:Bucket.
// The table below maps the tokens seen in real Pulumi YAML programs to the
// canonical types consumed by the rule packs, plus the provider label.
//
// Tokens absent from the table fall back to a sanitized derivation
// (see normalizeType): the provider prefix is kept and the type is
// snake_cased. Fallbacks emit a warning diagnostic so users know some
// rules may not apply.
package pulumi

import (
	"strings"
	"unicode"
)

type typeMapping struct {
	tfType   string // canonical type, e.g. aws_s3_bucket
	provider string // aws | azure | gcp
}

var pulumiTypeTable = map[string]typeMapping{
	// ---- AWS (aws classic provider) ----
	"aws:s3:Bucket":                                    {"aws_s3_bucket", "aws"},
	"aws:s3:BucketV2":                                  {"aws_s3_bucket", "aws"},
	"aws:s3:BucketPolicy":                              {"aws_s3_bucket_policy", "aws"},
	"aws:s3:BucketAcl":                                 {"aws_s3_bucket_acl", "aws"},
	"aws:s3:BucketAclV2":                               {"aws_s3_bucket_acl", "aws"},
	"aws:s3:BucketVersioning":                          {"aws_s3_bucket_versioning", "aws"},
	"aws:s3:BucketVersioningV2":                        {"aws_s3_bucket_versioning", "aws"},
	"aws:s3:BucketServerSideEncryptionConfiguration":   {"aws_s3_bucket_server_side_encryption_configuration", "aws"},
	"aws:s3:BucketServerSideEncryptionConfigurationV2": {"aws_s3_bucket_server_side_encryption_configuration", "aws"},
	"aws:s3:BucketPublicAccessBlock":                   {"aws_s3_bucket_public_access_block", "aws"},
	"aws:s3:BucketLogging":                             {"aws_s3_bucket_logging", "aws"},
	"aws:s3:BucketLoggingV2":                           {"aws_s3_bucket_logging", "aws"},
	"aws:s3:BucketNotification":                        {"aws_s3_bucket_notification", "aws"},
	"aws:s3:BucketReplicationConfig":                   {"aws_s3_bucket_replication_configuration", "aws"},
	"aws:ec2:Instance":                                 {"aws_instance", "aws"},
	"aws:ec2:SecurityGroup":                            {"aws_security_group", "aws"},
	"aws:ec2:Vpc":                                      {"aws_vpc", "aws"},
	"aws:ec2:Subnet":                                   {"aws_subnet", "aws"},
	"aws:ec2:InternetGateway":                          {"aws_internet_gateway", "aws"},
	"aws:ec2:RouteTable":                               {"aws_route_table", "aws"},
	"aws:ec2:Route":                                    {"aws_route", "aws"},
	"aws:ec2:EbsVolume":                                {"aws_ebs_volume", "aws"},
	"aws:ec2:Snapshot":                                 {"aws_ebs_snapshot", "aws"},
	"aws:ec2:LaunchTemplate":                           {"aws_launch_template", "aws"},
	"aws:ec2:KeyPair":                                  {"aws_key_pair", "aws"},
	"aws:ec2:NetworkAcl":                               {"aws_network_acl", "aws"},
	"aws:ec2:NetworkAclRule":                           {"aws_network_acl_rule", "aws"},
	"aws:iam:Role":                                     {"aws_iam_role", "aws"},
	"aws:iam:Policy":                                   {"aws_iam_policy", "aws"},
	"aws:iam:RolePolicy":                               {"aws_iam_role_policy", "aws"},
	"aws:iam:RolePolicyAttachment":                     {"aws_iam_role_policy_attachment", "aws"},
	"aws:iam:User":                                     {"aws_iam_user", "aws"},
	"aws:iam:UserPolicy":                               {"aws_iam_user_policy", "aws"},
	"aws:iam:Group":                                    {"aws_iam_group", "aws"},
	"aws:iam:AccessKey":                                {"aws_iam_access_key", "aws"},
	"aws:iam:InstanceProfile":                          {"aws_iam_instance_profile", "aws"},
	"aws:rds:Instance":                                 {"aws_db_instance", "aws"},
	"aws:rds:Cluster":                                  {"aws_rds_cluster", "aws"},
	"aws:rds:ClusterInstance":                          {"aws_rds_cluster_instance", "aws"},
	"aws:rds:ParameterGroup":                           {"aws_db_parameter_group", "aws"},
	"aws:rds:SubnetGroup":                              {"aws_db_subnet_group", "aws"},
	"aws:lambda:Function":                              {"aws_lambda_function", "aws"},
	"aws:lambda:Permission":                            {"aws_lambda_permission", "aws"},
	"aws:lambda:EventSourceMapping":                    {"aws_lambda_event_source_mapping", "aws"},
	"aws:elb:LoadBalancer":                             {"aws_elb", "aws"},
	"aws:lb:LoadBalancer":                              {"aws_lb", "aws"},
	"aws:lb:Listener":                                  {"aws_lb_listener", "aws"},
	"aws:lb:TargetGroup":                               {"aws_lb_target_group", "aws"},
	"aws:cloudtrail:Trail":                             {"aws_cloudtrail", "aws"},
	"aws:kms:Key":                                      {"aws_kms_key", "aws"},
	"aws:kms:Alias":                                    {"aws_kms_alias", "aws"},
	"aws:secretsmanager:Secret":                        {"aws_secretsmanager_secret", "aws"},
	"aws:secretsmanager:SecretVersion":                 {"aws_secretsmanager_secret_version", "aws"},
	"aws:ssm:Parameter":                                {"aws_ssm_parameter", "aws"},
	"aws:sqs:Queue":                                    {"aws_sqs_queue", "aws"},
	"aws:sqs:QueuePolicy":                              {"aws_sqs_queue_policy", "aws"},
	"aws:sns:Topic":                                    {"aws_sns_topic", "aws"},
	"aws:sns:TopicPolicy":                              {"aws_sns_topic_policy", "aws"},
	"aws:dynamodb:Table":                               {"aws_dynamodb_table", "aws"},
	"aws:ebs:Volume":                                   {"aws_ebs_volume", "aws"},
	"aws:eks:Cluster":                                  {"aws_eks_cluster", "aws"},
	"aws:eks:NodeGroup":                                {"aws_eks_node_group", "aws"},
	"aws:ecs:Cluster":                                  {"aws_ecs_cluster", "aws"},
	"aws:ecs:Service":                                  {"aws_ecs_service", "aws"},
	"aws:ecs:TaskDefinition":                           {"aws_ecs_task_definition", "aws"},
	"aws:cloudfront:Distribution":                      {"aws_cloudfront_distribution", "aws"},
	"aws:route53:Zone":                                 {"aws_route53_zone", "aws"},
	"aws:route53:Record":                               {"aws_route53_record", "aws"},
	"aws:acm:Certificate":                              {"aws_acm_certificate", "aws"},
	"aws:apigateway:RestApi":                           {"aws_api_gateway_rest_api", "aws"},
	"aws:apigateway:Stage":                             {"aws_api_gateway_stage", "aws"},
	"aws:apigatewayv2:Api":                             {"aws_apigatewayv2_api", "aws"},
	"aws:apigatewayv2:Stage":                           {"aws_apigatewayv2_stage", "aws"},
	"aws:redshift:Cluster":                             {"aws_redshift_cluster", "aws"},
	"aws:elasticache:Cluster":                          {"aws_elasticache_cluster", "aws"},
	"aws:elasticache:ReplicationGroup":                 {"aws_elasticache_replication_group", "aws"},
	"aws:elasticache:User":                             {"aws_elasticache_user", "aws"},
	"aws:efs:FileSystem":                               {"aws_efs_file_system", "aws"},
	"aws:opensearch:Domain":                            {"aws_opensearch_domain", "aws"},
	"aws:msk:Cluster":                                  {"aws_msk_cluster", "aws"},
	"aws:memorydb:Cluster":                             {"aws_memorydb_cluster", "aws"},
	"aws:cloudwatch:LogGroup":                          {"aws_cloudwatch_log_group", "aws"},
	"aws:cloudwatch:MetricAlarm":                       {"aws_cloudwatch_metric_alarm", "aws"},
	"aws:wafv2:WebAcl":                                 {"aws_wafv2_web_acl", "aws"},
	"aws:backup:Vault":                                 {"aws_backup_vault", "aws"},
	"aws:backup:Plan":                                  {"aws_backup_plan", "aws"},
	"aws:guardduty:Detector":                           {"aws_guardduty_detector", "aws"},
	"aws:config:Recorder":                              {"aws_config_configuration_recorder", "aws"},
	"aws:codebuild:Project":                            {"aws_codebuild_project", "aws"},

	// ---- Azure (azure-native provider) ----
	"azure-native:storage:StorageAccount":          {"azurerm_storage_account", "azure"},
	"azure-native:storage:BlobContainer":           {"azurerm_storage_container", "azure"},
	"azure-native:keyvault:Vault":                  {"azurerm_key_vault", "azure"},
	"azure-native:resources:ResourceGroup":         {"azurerm_resource_group", "azure"},
	"azure-native:authorization:RoleAssignment":    {"azurerm_role_assignment", "azure"},
	"azure-native:network:VirtualNetwork":          {"azurerm_virtual_network", "azure"},
	"azure-native:network:NetworkSecurityGroup":    {"azurerm_network_security_group", "azure"},
	"azure-native:network:PublicIPAddress":         {"azurerm_public_ip", "azure"},
	"azure-native:compute:VirtualMachine":          {"azurerm_virtual_machine", "azure"},
	"azure-native:sql:Server":                      {"azurerm_mssql_server", "azure"},
	"azure-native:sql:Database":                    {"azurerm_mssql_database", "azure"},
	"azure-native:sql:FirewallRule":                {"azurerm_mssql_firewall_rule", "azure"},
	"azure-native:web:AppService":                  {"azurerm_app_service", "azure"},
	"azure-native:web:AppServicePlan":              {"azurerm_app_service_plan", "azure"},
	"azure-native:containerservice:ManagedCluster": {"azurerm_kubernetes_cluster", "azure"},
	"azure-native:containerregistry:Registry":      {"azurerm_container_registry", "azure"},
	"azure-native:documentdb:DatabaseAccount":      {"azurerm_cosmosdb_account", "azure"},
	"azure-native:operationalinsights:Workspace":   {"azurerm_log_analytics_workspace", "azure"},
	"azure-native:insights:Component":              {"azurerm_application_insights", "azure"},
	"azure-native:eventhub:Namespace":              {"azurerm_eventhub_namespace", "azure"},
	"azure-native:servicebus:Namespace":            {"azurerm_servicebus_namespace", "azure"},
	"azure-native:apimanagement:Service":           {"azurerm_api_management", "azure"},
	"azure-native:cdn:Profile":                     {"azurerm_cdn_profile", "azure"},
	"azure-native:frontdoor:FrontDoor":             {"azurerm_frontdoor", "azure"},
	"azure-native:recoveryservices:Vault":          {"azurerm_recovery_services_vault", "azure"},
	"azure-native:automation:AutomationAccount":    {"azurerm_automation_account", "azure"},
	"azure-native:cache:Redis":                     {"azurerm_redis_cache", "azure"},
	"azure-native:devices:IotHubResource":          {"azurerm_iothub", "azure"},
	"azure-native:cognitiveservices:Account":       {"azurerm_cognitive_account", "azure"},
	"azure-native:datafactory:Factory":             {"azurerm_data_factory", "azure"},

	// ---- GCP (gcp provider) ----
	"gcp:storage:Bucket":              {"google_storage_bucket", "gcp"},
	"gcp:storage:BucketIAMBinding":    {"google_storage_bucket_iam_binding", "gcp"},
	"gcp:compute:Instance":            {"google_compute_instance", "gcp"},
	"gcp:compute:Network":             {"google_compute_network", "gcp"},
	"gcp:compute:Subnetwork":          {"google_compute_subnetwork", "gcp"},
	"gcp:compute:Firewall":            {"google_compute_firewall", "gcp"},
	"gcp:compute:Disk":                {"google_compute_disk", "gcp"},
	"gcp:compute:InstanceTemplate":    {"google_compute_instance_template", "gcp"},
	"gcp:sql:DatabaseInstance":        {"google_sql_database_instance", "gcp"},
	"gcp:container:Cluster":           {"google_container_cluster", "gcp"},
	"gcp:container:NodePool":          {"google_container_node_pool", "gcp"},
	"gcp:bigquery:Dataset":            {"google_bigquery_dataset", "gcp"},
	"gcp:bigquery:Table":              {"google_bigquery_table", "gcp"},
	"gcp:pubsub:Topic":                {"google_pubsub_topic", "gcp"},
	"gcp:pubsub:Subscription":         {"google_pubsub_subscription", "gcp"},
	"gcp:secretmanager:Secret":        {"google_secret_manager_secret", "gcp"},
	"gcp:kms:KeyRing":                 {"google_kms_key_ring", "gcp"},
	"gcp:kms:CryptoKey":               {"google_kms_crypto_key", "gcp"},
	"gcp:dns:ManagedZone":             {"google_dns_managed_zone", "gcp"},
	"gcp:cloudrun:Service":            {"google_cloud_run_service", "gcp"},
	"gcp:functions:Function":          {"google_cloudfunctions_function", "gcp"},
	"gcp:redis:Instance":              {"google_redis_instance", "gcp"},
	"gcp:spanner:Instance":            {"google_spanner_instance", "gcp"},
	"gcp:spanner:Database":            {"google_spanner_database", "gcp"},
	"gcp:artifactregistry:Repository": {"google_artifact_registry_repository", "gcp"},
	"gcp:serviceaccount:Account":      {"google_service_account", "gcp"},
	"gcp:serviceaccount:Key":          {"google_service_account_key", "gcp"},
	"gcp:projects:IAMBinding":         {"google_project_iam_binding", "gcp"},
	"gcp:projects:IAMMember":          {"google_project_iam_member", "gcp"},
	"gcp:logging:ProjectSink":         {"google_logging_project_sink", "gcp"},
	"gcp:monitoring:AlertPolicy":      {"google_monitoring_alert_policy", "gcp"},
	"gcp:dataproc:Cluster":            {"google_dataproc_cluster", "gcp"},
	"gcp:composer:Environment":        {"google_composer_environment", "gcp"},
	"gcp:ml:Model":                    {"google_vertex_ai_model", "gcp"},
	"gcp:bigtable:Instance":           {"google_bigtable_instance", "gcp"},
	"gcp:firestore:Database":          {"google_firestore_database", "gcp"},
	"gcp:cdn:BackendBucket":           {"google_compute_backend_bucket", "gcp"},
	"gcp:loadbalancing:URLMap":        {"google_compute_url_map", "gcp"},
}

// knownType reports whether the token has an explicit table entry.
func knownType(token string) bool {
	_, ok := pulumiTypeTable[token]
	return ok
}

// normalizeType maps a Pulumi type token to (canonical type, provider).
// Unknown tokens fall back to a sanitized derivation so the resource is
// still visible to the engine (named pulumi_<...>), with a warning.
func normalizeType(token string) (string, string) {
	if m, ok := pulumiTypeTable[token]; ok {
		return m.tfType, m.provider
	}
	provider := "pulumi"
	tfType := "pulumi_" + sanitizeToken(token)
	if parts := splitToken(token); len(parts) == 3 {
		switch parts[0] {
		case "aws":
			provider = "aws"
		case "azure-native", "azure":
			provider = "azure"
		case "gcp":
			provider = "gcp"
		}
	}
	return tfType, provider
}

// splitToken splits a type token on ':'.
func splitToken(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == ':' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

// sanitizeToken converts a type token to a safe lowercase identifier.
func sanitizeToken(token string) string {
	var b strings.Builder
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(unicode.ToLower(r))
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
