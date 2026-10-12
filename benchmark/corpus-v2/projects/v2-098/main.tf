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
