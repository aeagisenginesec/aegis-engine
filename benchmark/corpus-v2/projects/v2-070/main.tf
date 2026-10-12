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
