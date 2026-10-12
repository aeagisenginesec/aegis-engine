

resource "aws_db_instance" "core" {
  identifier                          = "core-db"
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


resource "aws_kms_key" "core_bv" {
  description             = "Backup vault encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_backup_vault" "core" {
  name        = "core-vault"
  kms_key_arn = aws_kms_key.core_bv.arn
}
