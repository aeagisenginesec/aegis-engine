resource "aws_db_instance" "legacy" {
  engine = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.small"
  identifier = "legacy-f52014"
  allocated_storage = 50
  storage_encrypted = false
  publicly_accessible = false
  username = "root"
  password = "Str0ng-f52014-Db!"
  backup_retention_period = 7
  skip_final_snapshot = true
}

resource "google_container_cluster" "main" {
  name = "main-f52014"
  location = "europe-west1"
  initial_node_count = 1
  master_authorized_networks_config {}
}
