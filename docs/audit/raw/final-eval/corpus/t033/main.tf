terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}
data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "main" {
  name     = "rg-app-dev"
  location = "West Europe"
}

resource "azurerm_key_vault" "app" {
  name                        = "acme-app-kv-01"
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 7
  purge_protection_enabled    = false
  enabled_for_disk_encryption = true

  tags = {
    environment = "dev"
  }
}

resource "azurerm_key_vault_access_policy" "deployer" {
  key_vault_id = azurerm_key_vault.app.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  key_permissions = [
    "Get", "Create", "Delete", "List", "Update",
    "Import", "Backup", "Restore", "Recover", "Purge"
  ]

  secret_permissions = [
    "Get", "Set", "Delete", "List", "Purge"
  ]
}

resource "azurerm_key_vault_secret" "db_password" {
  name         = "db-password"
  value        = "Sup3rSecret123!"
  key_vault_id = azurerm_key_vault.app.id
}
