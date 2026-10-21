resource "aws_db_instance" "prod" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"
  identifier = "prod-67356d"
  allocated_storage = 100
  storage_encrypted = true
  publicly_accessible = false
  username = "appadmin"
  password = "Str0ng-67356d-Db!"
  backup_retention_period = 14
  deletion_protection = true
  multi_az = true
  skip_final_snapshot = false
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  tags = { Name = "main" }
}

resource "azurerm_storage_account" "data" {
  name = "data67356d"
  resource_group_name = "rg-data"
  location = "westeurope"
  account_tier = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = false
  min_tls_version = "TLS1_2"
}

resource "azurerm_key_vault" "main" {
  name = "kv-67356d"
  location = "westeurope"
  resource_group_name = "rg-kv"
  sku_name = "standard"
  tenant_id = "00000000-0000-0000-0000-000000000000"
  purge_protection_enabled = true
  soft_delete_retention_days = 90
}
