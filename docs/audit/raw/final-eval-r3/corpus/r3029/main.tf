variable "db_password" {
  type = string
  default = "Sup3rSecret!-prod-2024"
  description = "Database master password"
}

resource "aws_db_instance" "app" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  identifier = "app-606553"
  allocated_storage = 20
  storage_encrypted = true
  username = "appadmin"
  password = var.db_password
  skip_final_snapshot = true
}

resource "azurerm_storage_account" "data" {
  name = "data606553"
  resource_group_name = "rg-data"
  location = "westeurope"
  account_tier = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = false
  min_tls_version = "TLS1_2"
}

resource "azurerm_key_vault" "main" {
  name = "kv-606553"
  location = "westeurope"
  resource_group_name = "rg-kv"
  sku_name = "standard"
  tenant_id = "00000000-0000-0000-0000-000000000000"
  purge_protection_enabled = true
  soft_delete_retention_days = 90
}

resource "aws_s3_bucket" "logs" {
  bucket = "app-logs-606553"
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
