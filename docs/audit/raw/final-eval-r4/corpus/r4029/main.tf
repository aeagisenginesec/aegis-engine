resource "aws_security_group" "app" {
  name = "app-651bc0"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["203.0.113.64/32"]
  }
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "azurerm_storage_account" "data" {
  name = "data651bc0"
  resource_group_name = "rg-data"
  location = "westeurope"
  account_tier = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = false
  min_tls_version = "TLS1_2"
}

resource "azurerm_key_vault" "main" {
  name = "kv-651bc0"
  location = "westeurope"
  resource_group_name = "rg-kv"
  sku_name = "standard"
  tenant_id = "00000000-0000-0000-0000-000000000000"
  purge_protection_enabled = true
  soft_delete_retention_days = 90
}
