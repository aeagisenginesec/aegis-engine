resource "aws_instance" "web" {
  ami = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  metadata_options {
    http_tokens = "required"
    http_endpoint = "enabled"
  }
  tags = { Name = "web-7d16c9" }
}

resource "azurerm_storage_account" "data" {
  name = "data7d16c9"
  resource_group_name = "rg-data"
  location = "westeurope"
  account_tier = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = false
  min_tls_version = "TLS1_2"
}

resource "azurerm_key_vault" "main" {
  name = "kv-7d16c9"
  location = "westeurope"
  resource_group_name = "rg-kv"
  sku_name = "standard"
  tenant_id = "00000000-0000-0000-0000-000000000000"
  purge_protection_enabled = true
  soft_delete_retention_days = 90
}
