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
  name     = "rg-secrets-prod"
  location = "North Europe"
}

resource "azurerm_key_vault" "app" {
  name                       = "acme-secrets-kv"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 90
  purge_protection_enabled   = true

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }

  tags = {
    environment = "prod"
  }
}
