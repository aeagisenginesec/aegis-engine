resource "aws_db_instance" "vuln" {
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
  storage_encrypted                  = true
  deletion_protection                = true
  publicly_accessible                = false
  backup_retention_period            = 7
  iam_database_authentication_enabled = true
  multi_az                           = true
  password = "HardcodedDBPassword123!"
}
