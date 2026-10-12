# Phase 3 sample-60 NEGATIVE fixtures (fixed/compliant). One resource per sampled rule.
# Expected: the listed rule does NOT fire on its resource.

# AEGIS-AWS-012: S3 bucket with versioning
resource "aws_s3_bucket" "s3_versioning" {
  bucket = "p3-sample-versioned"
}

resource "aws_s3_bucket_versioning" "s3_versioning" {
  bucket = aws_s3_bucket.s3_versioning.id

  versioning_configuration {
    status = "Enabled"
  }
}

# AEGIS-AWS-383: ECS cluster with Container Insights
resource "aws_ecs_cluster" "insights" {
  name = "p3-insights"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# AEGIS-AWS-371: Load balancer with access logs
resource "aws_lb" "logs" {
  name               = "p3-logs"
  load_balancer_type = "application"

  access_logs {
    bucket  = "p3-log-bucket"
    enabled = true
  }
}

# AEGIS-AWS-419: Athena workgroup configuration enforced
resource "aws_athena_workgroup" "enforced" {
  name                          = "p3-enforced"
  enforce_workgroup_configuration = true
}

# AEGIS-AWS-723: Lambda alias pointing at a published version
resource "aws_lambda_alias" "versioned" {
  name             = "p3-ver"
  function_name    = "p3-fn"
  function_version = "3"
}

# AEGIS-AWS-657: (no aws_iam_group_policy resource at all -> no finding)

# AEGIS-AWS-732: Lambda layer version with compatible runtimes
resource "aws_lambda_layer_version" "runtimes" {
  layer_name          = "p3-layer"
  filename            = "layer.zip"
  compatible_runtimes = ["python3.12"]
}

# AEGIS-AWS-736: ECS service with ECS Exec disabled
resource "aws_ecs_service" "exec_off" {
  name                   = "p3-noexec"
  enable_execute_command = false
}

# AEGIS-AWS-434: Glue job with security configuration
resource "aws_glue_job" "secconf" {
  name                   = "p3-glue"
  role_arn               = "arn:aws:iam::123456789012:role/p3"
  security_configuration = "p3-secconf"
}

# AEGIS-AWS-846: Route 53 health check enabled
resource "aws_route53_health_check" "enabled" {
  fqdn              = "example.com"
  port              = 443
  type              = "HTTPS"
  resource_path     = "/"
  failure_threshold = 3
  request_interval  = 30
  disabled          = false
}

# AEGIS-AWS-554: IAM role with 1-hour session duration
resource "aws_iam_role" "short_session" {
  name                 = "p3-short"
  max_session_duration = 3600
}

# AEGIS-AWS-571: CodeArtifact repository with upstream configuration
resource "aws_codeartifact_repository" "upstream" {
  repository = "p3-repo"
  domain     = "p3-domain"

  upstream {
    repository_name = "npm-store"
  }
}

# AEGIS-AWS-510: Load balancer listener with HTTP-to-HTTPS redirect
resource "aws_lb_listener" "redirect" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/p3/abc"
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# AEGIS-AWS-791: SSM SecureString parameter (not StringList)
resource "aws_ssm_parameter" "securestring" {
  name  = "/prod/db/password"
  type  = "SecureString"
  value = "hunter2"
}

# AEGIS-AWS-398: VPC peering connection with manual accept
resource "aws_vpc_peering_connection" "manual" {
  vpc_id      = "vpc-123"
  peer_vpc_id = "vpc-456"
  auto_accept = false
}

# AEGIS-AWS-816: App Runner service with encryption configuration
resource "aws_apprunner_service" "enc" {
  service_name = "p3-apprunner"

  encryption_configuration {
    kms_key = "arn:aws:kms:us-east-1:123456789012:key/abcd"
  }
}

# AEGIS-AWS-817: App Runner service with non-root health check path
resource "aws_apprunner_service" "hc" {
  service_name = "p3-apprunner-hc"

  health_check {
    path = "/healthz"
  }
}

# AEGIS-AWS-348: GuardDuty detector enabled
resource "aws_guardduty_detector" "on" {
  enable = true
}

# AEGIS-AWS-008: RDS instance with deletion protection
resource "aws_db_instance" "delprotect" {
  identifier          = "p3-db"
  deletion_protection = true
}

# AEGIS-AWS-570: CloudTrail bucket with MFA delete enabled
resource "aws_s3_bucket" "trail_bucket_ok" {
  bucket = "p3-trail-bucket-ok"
}

resource "aws_s3_bucket_versioning" "trail_bucket_ok_ver" {
  bucket = aws_s3_bucket.trail_bucket_ok.id

  versioning_configuration {
    status     = "Enabled"
    mfa_delete = "Enabled"
  }
}

resource "aws_cloudtrail" "trail_ok" {
  name           = "p3-trail-ok"
  s3_bucket_name = aws_s3_bucket.trail_bucket_ok.id
}

# AEGIS-AWS-523: OpenSearch domain with fine-grained access control
resource "aws_opensearch_domain" "fgac" {
  domain_name = "p3-search"

  advanced_security_options {
    enabled = true
  }
}

# AEGIS-AWS-516: EMR security configuration with in-transit encryption
resource "aws_emr_security_configuration" "transit" {
  name          = "p3-emr-sec"
  configuration = "{\"EncryptionConfiguration\": {\"EnableInTransitEncryption\": true}}"
}

# AEGIS-AWS-429: Neptune cluster with backup retention
resource "aws_neptune_cluster" "backup" {
  cluster_identifier      = "p3-neptune"
  backup_retention_period = 7
}

# AEGIS-AWS-638: Elasticsearch domain with dedicated master nodes
resource "aws_elasticsearch_domain" "master" {
  domain_name = "p3-es"

  cluster_config {
    dedicated_master_enabled = true
  }
}

# AEGIS-AZURE-130: AKS cluster with Microsoft Defender
resource "azurerm_kubernetes_cluster" "defender" {
  name     = "p3-aks"
  location = "westeurope"

  microsoft_defender {
    log_analytics_workspace_id = "/subscriptions/x/resourceGroups/y/providers/Microsoft.OperationalInsights/workspaces/z"
  }
}

# AEGIS-AZURE-297: Virtual machine with boot diagnostics
resource "azurerm_linux_virtual_machine" "bootdiag" {
  name     = "p3-vm"
  location = "westeurope"

  boot_diagnostics {
    storage_account_uri = "https://p3diag.blob.core.windows.net/"
  }
}

# AEGIS-AZURE-114: App Service with HTTP logging
resource "azurerm_app_service" "httplog" {
  name     = "p3-app"
  location = "westeurope"

  logs {
    http_logs {
      file_system {
        retention_in_days = 30
        retention_in_mb   = 35
      }
    }
  }
}

# AEGIS-AZURE-111: App Service with detailed error messages
resource "azurerm_app_service" "detailerr" {
  name     = "p3-app2"
  location = "westeurope"

  logs {
    detailed_error_messages_enabled = true
  }
}

# AEGIS-AZURE-165: Automation account with public network access disabled
resource "azurerm_automation_account" "nonet" {
  name                          = "p3-auto"
  location                      = "westeurope"
  public_network_access_enabled = false
}

# AEGIS-AZURE-309: Cognitive Services with deny-by-default network ACLs
resource "azurerm_cognitive_account" "deny_acls" {
  name     = "p3-cog"
  location = "westeurope"
  kind     = "OpenAI"

  network_acls {
    default_action = "Deny"
  }
}

# AEGIS-AZURE-047: MSSQL server with Azure AD administrator
resource "azurerm_mssql_server" "adadmin" {
  name     = "p3-sql"
  location = "westeurope"

  azuread_administrator {
    login_username = "p3admin"
    object_id      = "00000000-0000-0000-0000-000000000000"
  }
}

# AEGIS-AZURE-186: Key Vault soft-delete retention 90 days
resource "azurerm_key_vault" "retention_ok" {
  name                       = "p3-kv"
  location                   = "westeurope"
  soft_delete_retention_days = 90
}

# AEGIS-AZURE-194: Storage SAS policy blocking expired tokens
resource "azurerm_storage_account" "sas_block" {
  name     = "p3storageacct"
  location = "westeurope"

  sas_policy {
    expiration_action = "Block"
  }
}

# AEGIS-AZURE-038: Key Vault using RBAC authorization
resource "azurerm_key_vault" "rbac" {
  name                      = "p3-kv2"
  location                  = "westeurope"
  enable_rbac_authorization = true
}

# AEGIS-AZURE-129: AKS cluster with Key Vault secrets provider
resource "azurerm_kubernetes_cluster" "kvprovider" {
  name     = "p3-aks2"
  location = "westeurope"

  key_vault_secrets_provider {
    secret_rotation_enabled = true
  }
}

# AEGIS-AZURE-010: NSG rule scoped to private source
resource "azurerm_network_security_rule" "ssh_private" {
  name                       = "p3-ssh"
  direction                  = "Inbound"
  access                     = "Allow"
  protocol                   = "Tcp"
  source_port_range          = "*"
  destination_port_range     = "22"
  source_address_prefix      = "10.0.0.0/8"
  destination_address_prefix = "*"
}

# AEGIS-AZURE-295: Virtual machine with secure boot
resource "azurerm_linux_virtual_machine" "secureboot" {
  name                = "p3-vm2"
  location            = "westeurope"
  secure_boot_enabled = true
}

# AEGIS-AZURE-134: AKS cluster with cost analysis
resource "azurerm_kubernetes_cluster" "cost" {
  name                 = "p3-aks3"
  location             = "westeurope"
  cost_analysis_enabled = true
}

# AEGIS-GCP-267: Dataflow job with private IP configuration block present
resource "google_dataflow_job" "private_ip" {
  name = "p3-dataflow"

  ip_configuration {
  }
}

# AEGIS-GCP-151: (no google_service_account_iam_policy resource -> no finding)

# AEGIS-GCP-062: Compute instance with dedicated service account
resource "google_compute_instance" "custom_sa" {
  name = "p3-inst"

  service_account {
    email  = "p3-deployer@p3-project.iam.gserviceaccount.com"
    scopes = ["cloud-platform"]
  }
}

# AEGIS-GCP-132: Dataflow job with customer-managed encryption
resource "google_dataflow_job" "cmek" {
  name        = "p3-dataflow-cmek"
  kms_key_name = "projects/p3/locations/global/keyRings/p3/cryptoKeys/p3"
}

# AEGIS-GCP-239: Logging exclusion with narrow filter
resource "google_logging_project_exclusion" "narrow" {
  name   = "p3-excl"
  filter = "severity >= ERROR"
}

# AEGIS-GCP-045: Cloud SQL instance with local_infile off
resource "google_sql_database_instance" "no_local_infile" {
  name = "p3-sql"

  settings {
    database_flags {
      name  = "local_infile"
      value = "off"
    }
  }
}

# AEGIS-GCP-004: GKE cluster with master authorized networks
resource "google_container_cluster" "authnets" {
  name = "p3-gke"

  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "10.0.0.0/8"
      display_name = "internal"
    }
  }
}

# AEGIS-GCP-207: Pub/Sub topic with 7-day retention
resource "google_pubsub_topic" "retention_ok" {
  name                       = "p3-topic"
  message_retention_duration = "604800s"
}

# AEGIS-GCP-129: Cloud Run v2 service with deletion protection
resource "google_cloud_run_v2_service" "delprotect" {
  name                = "p3-run"
  deletion_protection = true
}

# AEGIS-GCP-087: Project with data-access audit logging
resource "google_project_iam_policy" "dataread" {
  project     = "p3-project"
  policy_data = "{}"

  audit_config {
    service = "allServices"

    audit_log_configs {
      log_type = "DATA_READ"
    }
  }
}

# AEGIS-GCP-199: Cloud Run service on GEN2 execution environment
resource "google_cloud_run_v2_service" "gen2" {
  name = "p3-run-gen2"

  template {
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
  }
}

# AEGIS-GCP-236: Log bucket with locked retention
resource "google_logging_project_bucket_config" "locked" {
  project        = "p3-project"
  location       = "global"
  bucket_id      = "p3-bucket"
  retention_days = 30
  locked         = true
}

# AEGIS-GCP-074: Project IAM grants Viewer to a group
resource "google_project_iam_member" "viewer_group" {
  project = "p3-project"
  role    = "roles/viewer"
  member  = "group:eng@example.com"
}

# AEGIS-GCP-242: Memorystore Redis with maintenance policy
resource "google_redis_instance" "maint" {
  name = "p3-redis"

  maintenance_policy {
    weekly_maintenance_window {
      day = "TUESDAY"
    }
  }
}

# AEGIS-ALI-004: OSS bucket with access logging
resource "alicloud_oss_bucket" "logging" {
  bucket = "p3-oss"

  logging {
    target_bucket = "p3-log-bucket"
  }
}
