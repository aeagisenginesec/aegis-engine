resource "aws_db_instance" "dev" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  identifier = "dev-8dc9d8"
  allocated_storage = 20
  storage_encrypted = true
  publicly_accessible = false
  username = "postgres"
  password = "password123"
  backup_retention_period = 7
  skip_final_snapshot = true
}

resource "azurerm_storage_account" "legacy" {
  name = "legacy8dc9d8"
  resource_group_name = "rg-legacy"
  location = "westeurope"
  account_tier = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = false
  min_tls_version = "TLS1_0"
}
