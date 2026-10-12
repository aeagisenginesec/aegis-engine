

resource "aws_db_instance" "analytics" {
  identifier                          = "analytics-db"
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

resource "aws_db_subnet_group" "analytics" {
  name       = "analytics-db-subnets"
  subnet_ids = ["subnet-aaa", "subnet-bbb"]
}
