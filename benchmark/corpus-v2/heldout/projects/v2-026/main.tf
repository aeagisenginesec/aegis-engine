resource "aws_db_instance" "orders" {
  engine                              = "postgres"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  username                            = "admin"
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  iam_database_authentication_enabled = true
  multi_az                            = true
  auto_minor_version_upgrade          = true
  copy_tags_to_snapshot               = true
  monitoring_interval                 = 60
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = "arn:aws:kms:us-east-1:123456789012:key/0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  enabled_cloudwatch_logs_log_exports = ["postgresql"]
}

output "db_master_password" {
  value = aws_db_instance.orders.password
}
