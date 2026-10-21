resource "aws_db_instance" "legacy" {
  engine = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.small"
  identifier = "legacy-7c4a65"
  allocated_storage = 50
  storage_encrypted = false
  publicly_accessible = false
  username = "root"
  password = "Str0ng-7c4a65-Db!"
  backup_retention_period = 7
  skip_final_snapshot = true
}
