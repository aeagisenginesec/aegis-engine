"""Corpus-v2 part B: 70 labeled vulnerable AWS Terraform projects.

Families: encryption gaps (25), logging blind spots (20), network
misconfigurations (25). Each project hardens everything EXCEPT the
vulnerability under test (silencer-snippet technique), so each project
isolates one issue family. All templates are original (not copied from
benchmark/labeled/generate_corpus.py) and every expected finding was
verified by running the aegis scanner against the rendered main.tf.
"""
PROJECTS = [
  {
    "local": "b-000",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_ecr_repository" "ledger" {
  name                 = "ledger-images"
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration {
    scan_on_push = true
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-515", "resource": "aws_ecr_repository.ledger", "severity": "medium", "issue": "ECR repository without KMS encryption_configuration"},
    ],
  },
  {
    "local": "b-001",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_emr_security_configuration" "analytics" {
  name = "analytics-sec"
  configuration = <<JSON
{
  "EncryptionConfiguration": {
    "EnableInTransitEncryption": false,
    "EnableAtRestEncryption": true
  }
}
JSON
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-516", "resource": "aws_emr_security_configuration.analytics", "severity": "medium", "issue": "EMR security configuration without in-transit encryption"},
    ],
  },
  {
    "local": "b-002",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_emr_security_configuration" "warehouse" {
  name = "warehouse-sec"
  configuration = <<JSON
{
  "EncryptionConfiguration": {
    "EnableInTransitEncryption": true,
    "EnableAtRestEncryption": false
  }
}
JSON
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-517", "resource": "aws_emr_security_configuration.warehouse", "severity": "medium", "issue": "EMR security configuration without local disk encryption"},
      {"rule_id": "AEGIS-AWS-361", "resource": "aws_emr_security_configuration.warehouse", "severity": "high", "issue": "EMR at-rest encryption explicitly disabled"},
    ],
  },
  {
    "local": "b-003",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_dax_cluster" "cache" {
  cluster_name       = "cache"
  iam_role_arn       = "arn:aws:iam::123456789012:role/dax"
  node_type          = "dax.r5.large"
  replication_factor = 2
  server_side_encryption {
    enabled = true
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-518", "resource": "aws_dax_cluster.cache", "severity": "medium", "issue": "DAX cluster without TLS endpoint encryption"},
    ],
  },
  {
    "local": "b-004",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_opensearch_domain" "search" {
  domain_name = "search"
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
  }
  cluster_config {
    instance_type            = "m6g.large.search"
    instance_count           = 2
    dedicated_master_enabled = true
    dedicated_master_type    = "m6g.large.search"
    dedicated_master_count   = 3
    zone_awareness_enabled   = true
  }
  vpc_options {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
  log_publishing_options {
    cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:search-audit"
    log_type                 = "AUDIT_LOGS"
  }
  log_publishing_options {
    cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:search-slow"
    log_type                 = "SEARCH_SLOW_LOGS"
  }
  snapshot_options {
    automated_snapshot_start_hour = 3
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-519", "resource": "aws_opensearch_domain.search", "severity": "medium", "issue": "OpenSearch domain with outdated TLS 1.0 policy"},
    ],
  },
  {
    "local": "b-005",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_transfer_server" "sftp" {
  endpoint_type        = "VPC"
  security_policy_name = "TransferSecurityPolicy-2018-11"
  logging_role         = "arn:aws:iam::123456789012:role/transfer-logging"
  endpoint_details {
    vpc_id             = "vpc-12345678"
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-520", "resource": "aws_transfer_server.sftp", "severity": "medium", "issue": "Transfer server with outdated 2018-11 security policy"},
    ],
  },
  {
    "local": "b-006",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_docdb_cluster" "ledger" {
  cluster_identifier              = "ledger"
  engine                          = "docdb"
  master_username                 = "admin"
  backup_retention_period         = 7
  deletion_protection             = true
  enabled_cloudwatch_logs_exports = ["audit", "profiler"]
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-351", "resource": "aws_docdb_cluster.ledger", "severity": "high", "issue": "DocumentDB cluster without storage encryption"},
    ],
  },
  {
    "local": "b-007",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_neptune_cluster" "graph" {
  cluster_identifier             = "graph"
  engine                         = "neptune"
  backup_retention_period              = 7
  deletion_protection                  = true
  iam_database_authentication_enabled  = true
  enable_cloudwatch_logs_exports       = ["audit"]
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-352", "resource": "aws_neptune_cluster.graph", "severity": "high", "issue": "Neptune cluster without storage encryption"},
    ],
  },
  {
    "local": "b-008",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_memorydb_cluster" "session" {
  cluster_name             = "session"
  node_type                = "db.r6g.large"
  acl_name                 = "open-access"
  tls_enabled              = false
  snapshot_retention_limit = 7
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-354", "resource": "aws_memorydb_cluster.session", "severity": "high", "issue": "MemoryDB cluster without TLS"},
    ],
  },
  {
    "local": "b-009",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_rds_cluster" "ledger" {
  cluster_identifier                  = "ledger"
  engine                              = "aurora-mysql"
  master_username                     = "admin"
  deletion_protection                 = true
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["audit"]
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/abc"
  monitoring_interval                 = 60
  backup_retention_period             = 7
  backtrack_window                    = 86400
  copy_tags_to_snapshot               = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-359", "resource": "aws_rds_cluster.ledger", "severity": "high", "issue": "Aurora cluster without storage encryption"},
      {"rule_id": "AEGIS-AWS-634", "resource": "aws_rds_cluster.ledger", "severity": "high", "issue": "Aurora cluster without customer-managed KMS key"},
    ],
  },
  {
    "local": "b-010",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_rds_cluster" "vault" {
  cluster_identifier                  = "vault"
  engine                              = "aurora-postgresql"
  master_username                     = "admin"
  storage_encrypted                   = true
  deletion_protection                 = true
  iam_database_authentication_enabled = true
  enabled_cloudwatch_logs_exports     = ["audit"]
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/abc"
  monitoring_interval                 = 60
  backup_retention_period             = 7
  copy_tags_to_snapshot               = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-634", "resource": "aws_rds_cluster.vault", "severity": "high", "issue": "Aurora cluster encrypted but without customer-managed KMS key"},
    ],
  },
  {
    "local": "b-011",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_launch_template" "worker" {
  name          = "worker"
  image_id      = "ami-12345678"
  instance_type = "t3.micro"
  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size = 30
      encrypted   = false
    }
  }
  metadata_options {
    http_tokens = "required"
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-301", "resource": "aws_launch_template.worker", "severity": "high", "issue": "Launch template with unencrypted EBS volume"},
    ],
  },
  {
    "local": "b-012",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_lambda_function" "worker" {
  function_name = "worker"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.13"
  handler       = "index.handler"
  environment {
    variables = {
      LOG_LEVEL = "info"
    }
  }
  tracing_config {
    mode = "Active"
  }
  vpc_config {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
  reserved_concurrent_executions = 10
  code_signing_config {
  }
  dead_letter_config {
    target_arn = "arn:aws:sqs:us-east-1:123456789012:worker-dlq"
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-307", "resource": "aws_lambda_function.worker", "severity": "high", "issue": "Lambda environment variables without KMS encryption"},
    ],
  },
  {
    "local": "b-013",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_dms_endpoint" "source" {
  endpoint_id   = "source"
  endpoint_type = "source"
  engine_name   = "postgres"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-357", "resource": "aws_dms_endpoint.source", "severity": "high", "issue": "DMS endpoint with default plaintext SSL mode"},
    ],
  },
  {
    "local": "b-014",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_redshiftserverless_namespace" "analytics" {
  namespace_name = "analytics"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-432", "resource": "aws_redshiftserverless_namespace.analytics", "severity": "medium", "issue": "Redshift Serverless namespace without customer-managed KMS key"},
    ],
  },
  {
    "local": "b-015",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_timestreamwrite_database" "metrics" {
  database_name = "metrics"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-435", "resource": "aws_timestreamwrite_database.metrics", "severity": "medium", "issue": "Timestream database without customer-managed KMS key"},
    ],
  },
  {
    "local": "b-016",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_db_proxy" "ledger" {
  name                   = "ledger"
  engine_family          = "POSTGRESQL"
  role_arn               = "arn:aws:iam::123456789012:role/db-proxy"
  vpc_subnet_ids         = ["subnet-12345678"]
  vpc_security_group_ids = ["sg-12345678"]
  auth {
    auth_scheme = "SECRETS"
    iam_auth    = "REQUIRED"
    secret_arn  = "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-creds"
  }
  require_tls = false
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-436", "resource": "aws_db_proxy.ledger", "severity": "high", "issue": "RDS proxy without TLS enforcement"},
    ],
  },
  {
    "local": "b-017",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_kms_grant" "ops" {
  name              = "ops"
  key_id            = "arn:aws:kms:us-east-1:123456789012:key/abc"
  grantee_principal = "arn:aws:iam::123456789012:role/ops"
  operations        = ["*"]
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-562", "resource": "aws_kms_grant.ops", "severity": "medium", "issue": "KMS grant with wildcard operations"},
    ],
  },
  {
    "local": "b-018",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_db_instance" "ledger" {
  engine                              = "postgres"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "admin"
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  multi_az                            = true
  iam_database_authentication_enabled = true
  performance_insights_enabled        = true
  monitoring_interval                 = 60
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  enabled_cloudwatch_logs_log_exports = ["postgresql"]
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-566", "resource": "aws_db_instance.ledger", "severity": "medium", "issue": "RDS Performance Insights without customer-managed KMS key"},
    ],
  },
  {
    "local": "b-019",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_codebuild_project" "build" {
  name         = "build"
  service_role = "arn:aws:iam::123456789012:role/codebuild"
  artifacts {
    type                = "S3"
    location            = "build-artifacts-bucket"
    encryption_disabled = true
  }
  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/standard:7.0"
    type         = "LINUX_CONTAINER"
  }
  source {
    type     = "GITHUB"
    location = "https://github.com/example/app"
  }
  logs_config {
    cloudwatch_logs {
      status = "ENABLED"
    }
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-384", "resource": "aws_codebuild_project.build", "severity": "medium", "issue": "CodeBuild artifacts with encryption disabled"},
    ],
  },
  {
    "local": "b-020",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_codepipeline" "deploy" {
  name     = "deploy"
  role_arn = "arn:aws:iam::123456789012:role/codepipeline"
  artifact_store {
    location = "deploy-artifacts-bucket"
    type     = "S3"
  }
  stage {
    name = "Source"
    action {
      name             = "Source"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["src"]
    }
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-386", "resource": "aws_codepipeline.deploy", "severity": "medium", "issue": "CodePipeline artifact store without KMS encryption"},
    ],
  },
  {
    "local": "b-021",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_athena_workgroup" "analytics" {
  name                            = "analytics"
  enforce_workgroup_configuration = false
  configuration {
    result_configuration {
      output_location = "s3://athena-results-bucket/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-419", "resource": "aws_athena_workgroup.analytics", "severity": "medium", "issue": "Athena workgroup configuration not enforced"},
    ],
  },
  {
    "local": "b-022",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_kms_key" "ledger" {
  description         = "ledger"
  enable_key_rotation = true
  policy              = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}
POLICY
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-420", "resource": "aws_kms_key.ledger", "severity": "high", "issue": "KMS key policy allows public principal"},
    ],
  },
  {
    "local": "b-023",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_elasticache_replication_group" "session" {
  replication_group_id       = "session"
  description                = "session"
  node_type                  = "cache.r6g.large"
  num_cache_clusters         = 2
  transit_encryption_enabled   = true
  at_rest_encryption_enabled   = true
  snapshot_retention_limit     = 7
  automatic_failover_enabled   = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-514", "resource": "aws_elasticache_replication_group.session", "severity": "high", "issue": "ElastiCache transit encryption without auth token"},
    ],
  },
  {
    "local": "b-024",
    "category": "encryption",
    "files": {"main.tf": """\
resource "aws_glue_job" "etl" {
  name     = "etl"
  role_arn = "arn:aws:iam::123456789012:role/glue"
  command {
    script_location = "s3://etl-scripts-bucket/job.py"
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-434", "resource": "aws_glue_job.etl", "severity": "medium", "issue": "Glue job without security configuration"},
    ],
  },
  {
    "local": "b-025",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_cloudtrail" "audit" {
  name                          = "audit"
  s3_bucket_name                = "audit-logs-bucket"
  kms_key_id                    = "arn:aws:kms:us-east-1:123456789012:key/abc"
  is_multi_region_trail         = true
  include_global_service_events = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-010", "resource": "aws_cloudtrail.audit", "severity": "medium", "issue": "CloudTrail without log file validation"},
    ],
  },
  {
    "local": "b-026",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_cloudtrail" "audit" {
  name                          = "audit"
  s3_bucket_name                = "audit-logs-bucket"
  enable_log_file_validation    = true
  is_multi_region_trail         = true
  include_global_service_events = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-568", "resource": "aws_cloudtrail.audit", "severity": "medium", "issue": "CloudTrail log files without KMS encryption"},
    ],
  },
  {
    "local": "b-027",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-209", "resource": "aws_vpc.main", "severity": "medium", "issue": "VPC without flow logs"},
    ],
  },
  {
    "local": "b-028",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_eks_cluster" "prod" {
  name     = "prod"
  role_arn = "arn:aws:iam::123456789012:role/eks"
  encryption_config {
    provider {
      key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc"
    }
    resources = ["secrets"]
  }
  vpc_config {
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-306", "resource": "aws_eks_cluster.prod", "severity": "medium", "issue": "EKS cluster without control plane logging"},
    ],
  },
  {
    "local": "b-029",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_lambda_function" "worker" {
  function_name = "worker"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.13"
  handler       = "index.handler"
  vpc_config {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
  reserved_concurrent_executions = 10
  code_signing_config {
  }
  dead_letter_config {
    target_arn = "arn:aws:sqs:us-east-1:123456789012:worker-dlq"
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-308", "resource": "aws_lambda_function.worker", "severity": "medium", "issue": "Lambda function without active X-Ray tracing"},
      {"rule_id": "AEGIS-AWS-547", "resource": "aws_lambda_function.worker", "severity": "low", "issue": "Lambda function without tracing configuration"},
    ],
  },
  {
    "local": "b-030",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
  }
  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 30
    encrypted   = true
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-310", "resource": "aws_instance.web", "severity": "medium", "issue": "EC2 instance without detailed monitoring"},
    ],
  },
  {
    "local": "b-031",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_api_gateway_rest_api" "api" {
  name = "api"
}

resource "aws_api_gateway_deployment" "prod" {
  rest_api_id = aws_api_gateway_rest_api.api.id
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  deployment_id = aws_api_gateway_deployment.prod.id
  stage_name    = "prod"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-327", "resource": "aws_api_gateway_stage.prod", "severity": "medium", "issue": "API Gateway stage without access logging"},
    ],
  },
  {
    "local": "b-032",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_apigatewayv2_api" "api" {
  name          = "api"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "prod"
  auto_deploy = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-332", "resource": "aws_apigatewayv2_stage.prod", "severity": "medium", "issue": "API Gateway v2 stage without access logging"},
    ],
  },
  {
    "local": "b-033",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_lb" "internal" {
  name                       = "internal"
  internal                   = true
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-371", "resource": "aws_lb.internal", "severity": "medium", "issue": "Load balancer without access logs"},
      {"rule_id": "AEGIS-AWS-609", "resource": "aws_lb.internal", "severity": "low", "issue": "Load balancer without access logging (hygiene)"},
    ],
  },
  {
    "local": "b-034",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_sfn_state_machine" "etl" {
  name     = "etl"
  role_arn = "arn:aws:iam::123456789012:role/sfn"
  definition = <<JSON
{
  "StartAt": "Done",
  "States": {
    "Done": { "Type": "Pass", "End": true }
  }
}
JSON
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-376", "resource": "aws_sfn_state_machine.etl", "severity": "medium", "issue": "Step Functions state machine without logging"},
      {"rule_id": "AEGIS-AWS-377", "resource": "aws_sfn_state_machine.etl", "severity": "medium", "issue": "Step Functions state machine without X-Ray tracing"},
    ],
  },
  {
    "local": "b-035",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_transfer_server" "sftp" {
  endpoint_type = "VPC"
  endpoint_details {
    vpc_id             = "vpc-12345678"
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-380", "resource": "aws_transfer_server.sftp", "severity": "medium", "issue": "Transfer server without CloudWatch logging role"},
    ],
  },
  {
    "local": "b-036",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_ecs_cluster" "prod" {
  name = "prod"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-383", "resource": "aws_ecs_cluster.prod", "severity": "medium", "issue": "ECS cluster without Container Insights"},
    ],
  },
  {
    "local": "b-037",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_s3_bucket" "archive" {
  bucket = "archive"
  lifecycle_rule {
    id      = "expire-old"
    enabled = true
    expiration {
      days = 365
    }
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 30
    }
  }
}

resource "aws_s3_bucket_policy" "archive" {
  bucket = aws_s3_bucket.archive.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::archive", "arn:aws:s3:::archive/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}
POLICY
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-445", "resource": "aws_s3_bucket.archive", "severity": "medium", "issue": "S3 bucket without server access logging"},
    ],
  },
  {
    "local": "b-038",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_db_instance" "ledger" {
  engine                              = "postgres"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "admin"
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  multi_az                            = true
  iam_database_authentication_enabled = true
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/abc"
  enabled_cloudwatch_logs_log_exports = ["postgresql"]
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-605", "resource": "aws_db_instance.ledger", "severity": "low", "issue": "RDS instance without enhanced monitoring"},
    ],
  },
  {
    "local": "b-039",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_db_instance" "orders" {
  engine                              = "postgres"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "admin"
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  multi_az                            = true
  iam_database_authentication_enabled = true
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/abc"
  monitoring_interval                 = 60
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-607", "resource": "aws_db_instance.orders", "severity": "low", "issue": "RDS Postgres instance without query logging export"},
    ],
  },
  {
    "local": "b-040",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_db_instance" "billing" {
  engine                              = "postgres"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "admin"
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  multi_az                            = true
  iam_database_authentication_enabled = true
  monitoring_interval                 = 60
  enabled_cloudwatch_logs_log_exports = ["postgresql"]
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-608", "resource": "aws_db_instance.billing", "severity": "low", "issue": "RDS instance without Performance Insights"},
    ],
  },
  {
    "local": "b-041",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_guardduty_detector" "main" {
  enable = false
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-348", "resource": "aws_guardduty_detector.main", "severity": "medium", "issue": "GuardDuty detector explicitly disabled"},
    ],
  },
  {
    "local": "b-042",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_cloudwatch_log_group" "app" {
  name       = "app"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-610", "resource": "aws_cloudwatch_log_group.app", "severity": "low", "issue": "CloudWatch log group without retention period"},
      {"rule_id": "AEGIS-AWS-347", "resource": "aws_cloudwatch_log_group.app", "severity": "medium", "issue": "CloudWatch log group with logs that never expire"},
    ],
  },
  {
    "local": "b-043",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_neptune_cluster" "graph" {
  cluster_identifier                = "graph"
  engine                            = "neptune"
  storage_encrypted                 = true
  backup_retention_period           = 7
  deletion_protection               = true
  iam_database_authentication_enabled = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-611", "resource": "aws_neptune_cluster.graph", "severity": "low", "issue": "Neptune cluster without CloudWatch log exports"},
    ],
  },
  {
    "local": "b-044",
    "category": "logging",
    "files": {"main.tf": """\
resource "aws_docdb_cluster" "ledger" {
  cluster_identifier      = "ledger"
  engine                  = "docdb"
  master_username         = "admin"
  storage_encrypted       = true
  backup_retention_period = 7
  deletion_protection     = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-624", "resource": "aws_docdb_cluster.ledger", "severity": "low", "issue": "DocumentDB cluster without CloudWatch log exports"},
    ],
  },
  {
    "local": "b-045",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_default_vpc" "default" {
  tags = {
    Name = "default"
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-396", "resource": "aws_default_vpc.default", "severity": "medium", "issue": "default VPC adopted instead of a custom VPC"},
    ],
  },
  {
    "local": "b-046",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_network_acl" "edge" {
  vpc_id = "vpc-12345678"
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/8"
    from_port  = 0
    to_port    = 0
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-328", "resource": "aws_network_acl.edge", "severity": "medium", "issue": "NACL ingress allows 0.0.0.0/0"},
    ],
  },
  {
    "local": "b-047",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_network_acl_rule" "open" {
  network_acl_id = "acl-12345678"
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 0
  to_port        = 0
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-331", "resource": "aws_network_acl_rule.open", "severity": "medium", "issue": "NACL rule allows ingress from 0.0.0.0/0"},
    ],
  },
  {
    "local": "b-048",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_lb" "edge" {
  name                       = "edge"
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-201", "resource": "aws_lb.edge", "severity": "high", "issue": "internet-facing load balancer"},
      {"rule_id": "AEGIS-AWS-506", "resource": "aws_lb.edge", "severity": "high", "issue": "public load balancer without WAF protection"},
    ],
  },
  {
    "local": "b-049",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name = "app.example.com"
    origin_id   = "app"
  }
  default_cache_behavior {
    target_origin_id       = "app"
    viewer_protocol_policy = "allow-all"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }
  viewer_certificate {
    acm_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/abc"
    ssl_support_method  = "sni-only"
  }
  logging_config {
    bucket = "cdn-logs-bucket.s3.amazonaws.com"
    prefix = "cdn/"
  }
  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "MA"]
    }
  }
  web_acl_id = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/cdn/abcd"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-325", "resource": "aws_cloudfront_distribution.cdn", "severity": "high", "issue": "CloudFront distribution allows plain HTTP"},
    ],
  },
  {
    "local": "b-050",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name = "app.example.com"
    origin_id   = "app"
  }
  default_cache_behavior {
    target_origin_id       = "app"
    viewer_protocol_policy = "https-only"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }
  viewer_certificate {
    acm_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/abc"
    ssl_support_method  = "sni-only"
  }
  logging_config {
    bucket = "cdn-logs-bucket.s3.amazonaws.com"
    prefix = "cdn/"
  }
  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = ["US", "MA"]
    }
  }

}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-330", "resource": "aws_cloudfront_distribution.cdn", "severity": "medium", "issue": "CloudFront distribution without WAF"},
    ],
  },
  {
    "local": "b-051",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name = "app.example.com"
    origin_id   = "app"
  }
  default_cache_behavior {
    target_origin_id       = "app"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }
  viewer_certificate {
    acm_certificate_arn = "arn:aws:acm:us-east-1:123456789012:certificate/abc"
    ssl_support_method  = "sni-only"
  }
  logging_config {
    bucket = "cdn-logs-bucket.s3.amazonaws.com"
    prefix = "cdn/"
  }
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  web_acl_id = "arn:aws:wafv2:us-east-1:123456789012:global/webacl/cdn/abcd"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-512", "resource": "aws_cloudfront_distribution.cdn", "severity": "medium", "issue": "CloudFront distribution without geo restriction"},
    ],
  },
  {
    "local": "b-052",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_api_gateway_domain_name" "api" {
  domain_name     = "api.example.com"
  security_policy = "TLS_1_0"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-326", "resource": "aws_api_gateway_domain_name.api", "severity": "high", "issue": "API Gateway custom domain with weak TLS policy"},
    ],
  },
  {
    "local": "b-053",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_lb_target_group" "app" {
  name     = "app"
  port     = 80
  protocol = "HTTP"
  vpc_id   = "vpc-12345678"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-329", "resource": "aws_lb_target_group.app", "severity": "high", "issue": "LB target group using plaintext HTTP"},
    ],
  },
  {
    "local": "b-054",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_opensearch_domain" "search" {
  domain_name = "search"
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
  }
  cluster_config {
    instance_type            = "m6g.large.search"
    instance_count           = 2
    dedicated_master_enabled = true
    dedicated_master_type    = "m6g.large.search"
    dedicated_master_count   = 3
    zone_awareness_enabled   = true
  }
  log_publishing_options {
    cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:search-audit"
    log_type                 = "AUDIT_LOGS"
  }
  log_publishing_options {
    cloudwatch_log_group_arn = "arn:aws:logs:us-east-1:123456789012:log-group:search-slow"
    log_type                 = "SEARCH_SLOW_LOGS"
  }
  snapshot_options {
    automated_snapshot_start_hour = 3
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-507", "resource": "aws_opensearch_domain.search", "severity": "high", "issue": "OpenSearch domain outside a VPC"},
    ],
  },
  {
    "local": "b-055",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier  = "warehouse"
  node_type           = "dc2.large"
  master_username     = "admin"
  encrypted           = true
  publicly_accessible = false
  enhanced_vpc_routing = true
  logging {
    bucket_name = "redshift-logs-bucket"
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-508", "resource": "aws_redshift_cluster.warehouse", "severity": "high", "issue": "Redshift cluster outside a VPC subnet group"},
    ],
  },
  {
    "local": "b-056",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_transfer_server" "sftp" {
  endpoint_type = "PUBLIC"
  logging_role  = "arn:aws:iam::123456789012:role/transfer-logging"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-509", "resource": "aws_transfer_server.sftp", "severity": "high", "issue": "Transfer server with public endpoint"},
    ],
  },
  {
    "local": "b-057",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_sagemaker_notebook_instance" "studio" {
  name          = "studio"
  role_arn      = "arn:aws:iam::123456789012:role/sagemaker"
  instance_type = "ml.t3.medium"
  kms_key_id    = "arn:aws:kms:us-east-1:123456789012:key/abc"
  direct_internet_access = "Disabled"
  instance_metadata_service_configuration {
    minimum_instance_metadata_service_version = 2
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-511", "resource": "aws_sagemaker_notebook_instance.studio", "severity": "medium", "issue": "SageMaker notebook not attached to a VPC subnet"},
    ],
  },
  {
    "local": "b-058",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_appsync_graphql_api" "api" {
  name                = "api"
  authentication_type = "AMAZON_COGNITO_USER_POOLS"
  xray_enabled        = true
  log_config {
    cloudwatch_logs_role_arn = "arn:aws:iam::123456789012:role/appsync-logging"
    field_log_level          = "ERROR"
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-513", "resource": "aws_appsync_graphql_api.api", "severity": "medium", "issue": "AppSync API without WAF protection"},
    ],
  },
  {
    "local": "b-059",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_ec2_transit_gateway_route_table_propagation" "spread" {
  transit_gateway_attachment_id  = "tgw-attach-12345678"
  transit_gateway_route_table_id = "tgw-rtb-12345678"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-556", "resource": "aws_ec2_transit_gateway_route_table_propagation.spread", "severity": "high", "issue": "Transit gateway route propagation enabled"},
    ],
  },
  {
    "local": "b-060",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = "vpc-12345678"
  service_name = "com.amazonaws.us-east-1.s3"
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-557", "resource": "aws_vpc_endpoint.s3", "severity": "medium", "issue": "VPC endpoint with default open policy"},
      {"rule_id": "AEGIS-AWS-433", "resource": "aws_vpc_endpoint.s3", "severity": "high", "issue": "VPC endpoint allows public principal"},
    ],
  },
  {
    "local": "b-061",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_ecs_task_definition" "worker" {
  family                   = "worker"
  network_mode             = "host"
  requires_compatibilities = ["EC2"]
  container_definitions    = <<JSON
[
  {
    "name": "worker",
    "image": "worker:latest",
    "cpu": 256,
    "memory": 512,
    "essential": true,
    "readonlyRootFilesystem": true
  }
]
JSON
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-412", "resource": "aws_ecs_task_definition.worker", "severity": "high", "issue": "ECS task definition with host networking"},
    ],
  },
  {
    "local": "b-062",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_eks_node_group" "worker" {
  cluster_name    = "prod"
  node_group_name = "worker"
  node_role_arn   = "arn:aws:iam::123456789012:role/eks-node"
  subnet_ids      = ["subnet-12345678"]
  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }
  remote_access {
    ec2_ssh_key = "prod-key"
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-413", "resource": "aws_eks_node_group.worker", "severity": "medium", "issue": "EKS node group with SSH remote access"},
    ],
  },
  {
    "local": "b-063",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_ecs_service" "web" {
  name            = "web"
  cluster         = "arn:aws:ecs:us-east-1:123456789012:cluster/prod"
  task_definition = "arn:aws:ecs:us-east-1:123456789012:task-definition/web:1"
  desired_count   = 2
  network_configuration {
    subnets          = ["subnet-12345678"]
    assign_public_ip = true
  }
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-381", "resource": "aws_ecs_service.web", "severity": "high", "issue": "ECS service tasks with public IP assignment"},
    ],
  },
  {
    "local": "b-064",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_dms_replication_instance" "mig" {
  replication_instance_id    = "mig"
  replication_instance_class = "dms.t3.micro"
  allocated_storage          = 50
  publicly_accessible        = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-356", "resource": "aws_dms_replication_instance.mig", "severity": "high", "issue": "DMS replication instance publicly accessible"},
    ],
  },
  {
    "local": "b-065",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_instance" "bastion" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  monitoring                  = true
  metadata_options {
    http_tokens = "required"
  }
  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 30
    encrypted   = true
  }
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-444", "resource": "aws_instance.bastion", "severity": "high", "issue": "EC2 instance with public IP association"},
    ],
  },
  {
    "local": "b-066",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_redshiftserverless_workgroup" "analytics" {
  namespace_name      = "analytics"
  workgroup_name      = "analytics"
  publicly_accessible = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-431", "resource": "aws_redshiftserverless_workgroup.analytics", "severity": "high", "issue": "Redshift Serverless workgroup publicly accessible"},
    ],
  },
  {
    "local": "b-067",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_appstream_fleet" "office" {
  name          = "office"
  instance_type = "stream.standard.small"
  fleet_type    = "ON_DEMAND"
  compute_capacity {
    desired_instances = 1
  }
  enable_default_internet_access = true
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-437", "resource": "aws_appstream_fleet.office", "severity": "medium", "issue": "AppStream fleet with default internet access"},
    ],
  },
  {
    "local": "b-068",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_s3_access_point" "data" {
  bucket = "data-bucket"
  name   = "data"
}

resource "aws_s3control_access_point_policy" "data" {
  access_point_arn = aws_s3_access_point.data.arn
  policy           = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:us-east-1:123456789012:accesspoint/data/object/*"
    }
  ]
}
POLICY
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-441", "resource": "aws_s3control_access_point_policy.data", "severity": "high", "issue": "S3 access point policy allows public principal"},
    ],
  },
  {
    "local": "b-069",
    "category": "network",
    "files": {"main.tf": """\
resource "aws_vpc_endpoint_service" "privatelink" {
  acceptance_required        = false
  network_load_balancer_arns = ["arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/x/abcd"]
}
"""},
    "vulnerable": True,
    "expected": [
      {"rule_id": "AEGIS-AWS-442", "resource": "aws_vpc_endpoint_service.privatelink", "severity": "medium", "issue": "VPC endpoint service without acceptance requirement"},
    ],
  },
]

# ---------------------------------------------------------------------------
# VERIFICATION SUMMARY
# ---------------------------------------------------------------------------
# Projects built: 70 (encryption=25, logging=20, network=25)
# Total expected findings: 78
# All verified firing: Y — every project was rendered to a temp dir and
# scanned with `aegis scan --format=json`; each expected (rule_id, resource,
# severity) tuple was observed, and no unexpected findings remained.
# Dropped expectations: none.
#
# Notes from verification (silencer adjustments, all re-verified green):
# - AEGIS-AWS-432 (redshiftserverless namespace, no CMK) is medium, not high.
# - Hygiene-family logging rules are low severity: 605, 607, 608, 609, 610,
#   611, 624 (and 547); their Severity() was read from scanner output.
# - 607 (rdsNoQueryLogging) keys off the quirk attribute
#   `enabled_cloudwatch_logs_log_exports` (not `enabled_cloudwatch_logs_exports`).
# - Genuine co-fires kept as multi-expectation projects (all scan-verified):
#   b-002: 517+361 (EMR at-rest disabled); b-009: 359+634 (Aurora unencrypted,
#   no CMK); b-033: 371+609 (LB access logs); b-034: 376+377 (SFN logging+xray);
#   b-042: 610+347 (log group retention); b-048: 201+506 (public LB, no WAF);
#   b-060: 557+433 (VPC endpoint open policy). b-029: 308+547 (lambda tracing).
# - 512 (cloudfrontNoGeoRestrict) only fires on explicit restriction_type=
#   "none"; an absent restrictions block is undecidable, not a finding.
# ---------------------------------------------------------------------------
