resource "aws_db_instance" "ephemeral" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  identifier = "ephemeral-4c2865"
  allocated_storage = 20
  storage_encrypted = true
  publicly_accessible = false
  username = "appadmin"
  password = "Str0ng-4c2865-Db!"
  backup_retention_period = 0
  skip_final_snapshot = true
}

resource "aws_db_instance" "dev" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  identifier = "dev-4c2865"
  allocated_storage = 20
  storage_encrypted = true
  publicly_accessible = false
  username = "postgres"
  password = "password123"
  backup_retention_period = 7
  skip_final_snapshot = true
}
