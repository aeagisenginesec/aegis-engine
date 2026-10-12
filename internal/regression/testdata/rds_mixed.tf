# Legacy MySQL: publicly accessible, unencrypted, no deletion protection,
# no backups, plaintext password in config. Next to it a hardened Postgres
# instance that should stay silent, so the fixture pins both true and false
# positives.
resource "aws_db_instance" "legacy" {
  identifier              = "legacy-mysql"
  engine                  = "mysql"
  engine_version          = "5.7"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "S3cretP@ssw0rd!"
  publicly_accessible     = true
  storage_encrypted       = false
  deletion_protection     = false
  backup_retention_period = 0
  skip_final_snapshot     = true
}

resource "aws_db_instance" "orders" {
  identifier              = "orders-postgres"
  engine                  = "postgres"
  engine_version          = "15"
  instance_class          = "db.t3.small"
  allocated_storage       = 50
  username                = "orders_app"
  publicly_accessible     = false
  storage_encrypted       = true
  deletion_protection     = true
  backup_retention_period = 7
  skip_final_snapshot     = false
}
