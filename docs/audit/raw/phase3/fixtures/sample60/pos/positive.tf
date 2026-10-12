# Phase 3 sample-60 POSITIVE fixtures (violating). One resource per sampled rule.
# Expected: each listed rule fires exactly on its resource.

# AEGIS-AWS-012: S3 bucket without versioning
resource "aws_s3_bucket" "s3_no_versioning" {
  bucket = "p3-sample-noversion"
}

# AEGIS-AWS-383: ECS cluster without Container Insights
resource "aws_ecs_cluster" "no_insights" {
  name = "p3-no-insights"
}

# AEGIS-AWS-371: Load balancer without access logs
resource "aws_lb" "no_logs" {
  name               = "p3-nologs"
  load_balancer_type = "application"
}

# AEGIS-AWS-419: Athena workgroup configuration not enforced
resource "aws_athena_workgroup" "not_enforced" {
  name = "p3-not-enforced"
}

# AEGIS-AWS-723: Lambda alias pointing at $LATEST
resource "aws_lambda_alias" "latest" {
  name             = "p3-latest"
  function_name    = "p3-fn"
  function_version = "$LATEST"
}

# AEGIS-AWS-657: IAM group uses an inline policy (fires on resource existence)
resource "aws_iam_group_policy" "inline" {
  name   = "p3-inline"
  group  = "p3-group"
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
}

# AEGIS-AWS-732: Lambda layer version without compatible runtimes
resource "aws_lambda_layer_version" "no_runtimes" {
  layer_name = "p3-layer"
  filename   = "layer.zip"
}

# AEGIS-AWS-736: ECS service with ECS Exec enabled
resource "aws_ecs_service" "exec_on" {
  name                   = "p3-exec"
  enable_execute_command = true
}

# AEGIS-AWS-434: Glue job without security configuration
resource "aws_glue_job" "no_secconf" {
  name     = "p3-glue"
  role_arn = "arn:aws:iam::123456789012:role/p3"
}

# AEGIS-AWS-846: Route 53 health check disabled
resource "aws_route53_health_check" "disabled" {
  fqdn              = "example.com"
  port              = 443
  type              = "HTTPS"
  resource_path     = "/"
  failure_threshold = 3
  request_interval  = 30
  disabled          = true
}

# AEGIS-AWS-554: IAM role with max session duration over 12 hours
resource "aws_iam_role" "long_session" {
  name                 = "p3-long"
  max_session_duration = 50000
}

# AEGIS-AWS-571: CodeArtifact repository without upstream configuration
resource "aws_codeartifact_repository" "no_upstream" {
  repository = "p3-repo"
  domain     = "p3-domain"
}

# AEGIS-AWS-510: Load balancer listener without HTTP-to-HTTPS redirect
resource "aws_lb_listener" "no_redirect" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/p3/abc"
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/p3/abc"
  }
}

# AEGIS-AWS-791: SSM StringList parameter stores plaintext secret
resource "aws_ssm_parameter" "plaintext_secret" {
  name  = "/prod/db/password"
  type  = "StringList"
  value = "hunter2"
}

# AEGIS-AWS-398: VPC peering connection auto-accept enabled
resource "aws_vpc_peering_connection" "auto_accept" {
  vpc_id      = "vpc-123"
  peer_vpc_id = "vpc-456"
  auto_accept = true
}

# AEGIS-AWS-816: App Runner service without encryption configuration
resource "aws_apprunner_service" "no_enc" {
  service_name = "p3-apprunner"
}

# AEGIS-AWS-817: App Runner service with root-path health check
resource "aws_apprunner_service" "root_hc" {
  service_name = "p3-apprunner-hc"

  health_check {
    path = "/"
  }
}

# AEGIS-AWS-348: GuardDuty detector disabled
resource "aws_guardduty_detector" "off" {
  enable = false
}

# AEGIS-AWS-008: RDS instance without deletion protection
resource "aws_db_instance" "no_delprotect" {
  identifier = "p3-db"
}

# AEGIS-AWS-570: CloudTrail S3 bucket without MFA delete protection
# (cross-resource: trail -> bucket -> versioning without mfa_delete=Enabled)
resource "aws_s3_bucket" "trail_bucket" {
  bucket = "p3-trail-bucket"
}

resource "aws_s3_bucket_versioning" "trail_bucket_ver" {
  bucket = "p3-trail-bucket"

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_cloudtrail" "trail" {
  name           = "p3-trail"
  s3_bucket_name = "p3-trail-bucket"
}

# AEGIS-AWS-523: OpenSearch domain without fine-grained access control
resource "aws_opensearch_domain" "no_fgac" {
  domain_name = "p3-search"
}

# AEGIS-AWS-516: EMR security configuration without in-transit encryption
resource "aws_emr_security_configuration" "no_transit" {
  name          = "p3-emr-sec"
  configuration = "{\"EncryptionConfiguration\": {\"EnableAtRestEncryption\": true}}"
}

# AEGIS-AWS-429: Neptune cluster without backup retention
resource "aws_neptune_cluster" "no_backup" {
  cluster_identifier = "p3-neptune"
}

# AEGIS-AWS-638: Elasticsearch domain without dedicated master nodes
resource "aws_elasticsearch_domain" "no_master" {
  domain_name = "p3-es"
}

# AEGIS-AZURE-130: AKS cluster without Microsoft Defender for Containers
resource "azurerm_kubernetes_cluster" "no_defender" {
  name     = "p3-aks"
  location = "westeurope"
}

# AEGIS-AZURE-297: Virtual machine without boot diagnostics
resource "azurerm_linux_virtual_machine" "no_bootdiag" {
  name     = "p3-vm"
  location = "westeurope"
}

# AEGIS-AZURE-114: App Service without HTTP logging
resource "azurerm_app_service" "no_httplog" {
  name     = "p3-app"
  location = "westeurope"
}

# AEGIS-AZURE-111: App Service without detailed error messages
resource "azurerm_app_service" "no_detailerr" {
  name     = "p3-app2"
  location = "westeurope"
}

# AEGIS-AZURE-165: Automation account with public network access enabled
resource "azurerm_automation_account" "pubnet" {
  name     = "p3-auto"
  location = "westeurope"
}

# AEGIS-AZURE-309: Cognitive Services with permissive network ACLs
resource "azurerm_cognitive_account" "open_acls" {
  name     = "p3-cog"
  location = "westeurope"
  kind     = "OpenAI"

  network_acls {
    default_action = "Allow"
  }
}

# AEGIS-AZURE-047: MSSQL server without Azure AD administrator
resource "azurerm_mssql_server" "no_adadmin" {
  name     = "p3-sql"
  location = "westeurope"
}

# AEGIS-AZURE-186: Key Vault soft-delete retention under 90 days
resource "azurerm_key_vault" "short_retention" {
  name                      = "p3-kv"
  location                  = "westeurope"
  soft_delete_retention_days = 7
}

# AEGIS-AZURE-194: Storage SAS policy not blocking expired tokens
resource "azurerm_storage_account" "sas_log" {
  name     = "p3storageacct"
  location = "westeurope"

  sas_policy {
  }
}

# AEGIS-AZURE-038: Key Vault not using RBAC authorization
resource "azurerm_key_vault" "no_rbac" {
  name                     = "p3-kv2"
  location                 = "westeurope"
  enable_rbac_authorization = false
}

# AEGIS-AZURE-129: AKS cluster without Key Vault secrets provider
resource "azurerm_kubernetes_cluster" "no_kvprovider" {
  name     = "p3-aks2"
  location = "westeurope"
}

# AEGIS-AZURE-010: NSG rule open to the internet on a sensitive port
resource "azurerm_network_security_rule" "ssh_open" {
  name                        = "p3-ssh"
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "0.0.0.0/0"
  destination_address_prefix  = "*"
}

# AEGIS-AZURE-295: Virtual machine without secure boot
resource "azurerm_linux_virtual_machine" "no_secureboot" {
  name     = "p3-vm2"
  location = "westeurope"
}

# AEGIS-AZURE-134: AKS cluster without cost analysis
resource "azurerm_kubernetes_cluster" "no_cost" {
  name     = "p3-aks3"
  location = "westeurope"
}

# AEGIS-GCP-267: Dataflow job without private IP configuration
resource "google_dataflow_job" "public_ip" {
  name = "p3-dataflow"
}

# AEGIS-GCP-151: Authoritative service account IAM policy (fires on existence)
resource "google_service_account_iam_policy" "authoritative" {
  service_account_id = "projects/p3/serviceAccounts/p3@p3.iam.gserviceaccount.com"
  policy_data        = "{}"
}

# AEGIS-GCP-062: Compute instance with default service account (empty email = default)
resource "google_compute_instance" "default_sa" {
  name = "p3-inst"

  service_account {
    scopes = ["cloud-platform"]
  }
}

# AEGIS-GCP-132: Dataflow job without customer-managed encryption
resource "google_dataflow_job" "no_cmek" {
  name = "p3-dataflow-nocmek"
}

# AEGIS-GCP-239: Logging exclusion excludes everything
resource "google_logging_project_exclusion" "broad" {
  name   = "p3-excl"
  filter = ""
}

# AEGIS-GCP-045: Cloud SQL instance with local_infile enabled
resource "google_sql_database_instance" "local_infile" {
  name = "p3-sql"

  settings {
    database_flags {
      name  = "local_infile"
      value = "on"
    }
  }
}

# AEGIS-GCP-004: GKE cluster without master authorized networks
resource "google_container_cluster" "no_authnets" {
  name = "p3-gke"
}

# AEGIS-GCP-207: Pub/Sub topic message retention under 7 days
resource "google_pubsub_topic" "short_retention" {
  name                       = "p3-topic"
  message_retention_duration = "86400s"
}

# AEGIS-GCP-129: Cloud Run v2 service without deletion protection
resource "google_cloud_run_v2_service" "no_delprotect" {
  name = "p3-run"
}

# AEGIS-GCP-087: Project without data-access audit logging
resource "google_project_iam_policy" "no_dataread" {
  project     = "p3-project"
  policy_data = "{}"

  audit_config {
    service = "allServices"

    audit_log_configs {
      log_type = "ADMIN_READ"
    }
  }
}

# AEGIS-GCP-199: Cloud Run service on first-generation execution environment
resource "google_cloud_run_v2_service" "gen1" {
  name = "p3-run-gen1"

  template {
    execution_environment = "EXECUTION_ENVIRONMENT_GEN1"
  }
}

# AEGIS-GCP-236: Log bucket retention not locked
resource "google_logging_project_bucket_config" "unlocked" {
  project        = "p3-project"
  location       = "global"
  bucket_id      = "p3-bucket"
  retention_days = 30
}

# AEGIS-GCP-074: Project IAM grants Viewer to individual user
resource "google_project_iam_member" "viewer_user" {
  project = "p3-project"
  role    = "roles/viewer"
  member  = "user:alice@example.com"
}

# AEGIS-GCP-242: Memorystore Redis without maintenance policy
resource "google_redis_instance" "no_maint" {
  name = "p3-redis"
}

# AEGIS-ALI-004: OSS bucket without access logging
resource "alicloud_oss_bucket" "no_logging" {
  bucket = "p3-oss"
}
