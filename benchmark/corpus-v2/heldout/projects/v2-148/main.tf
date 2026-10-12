

resource "aws_db_instance" "catalog" {
  identifier                          = "catalog-db"
  engine                              = "mysql"
  engine_version                      = "8.0"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  multi_az                            = true
  iam_database_authentication_enabled = true
  manage_master_user_password         = true
  enabled_cloudwatch_logs_exports     = ["error", "slowquery"]
}
