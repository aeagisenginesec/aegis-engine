resource "aws_db_instance" "vuln" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  publicly_accessible = false
  deletion_protection               = true
  backup_retention_period           = 7
  iam_database_authentication_enabled = true
  multi_az                          = true
}
