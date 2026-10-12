

resource "aws_db_instance" "users" {
  identifier                          = "users-db"
  engine                              = "postgres"
  engine_version                      = "15.4"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  multi_az                            = true
  iam_database_authentication_enabled = true
  manage_master_user_password         = true
  enabled_cloudwatch_logs_exports     = ["postgresql"]
}

resource "aws_db_instance" "users_ro" {
  identifier                          = "users_ro-db"
  engine                              = "postgres"
  engine_version                      = "15.4"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  multi_az                            = true
  iam_database_authentication_enabled = true
  manage_master_user_password         = true
  enabled_cloudwatch_logs_exports     = ["postgresql"]
}
