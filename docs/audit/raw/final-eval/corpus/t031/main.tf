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
resource "azurerm_resource_group" "main" {
  name     = "rg-media-prod"
  location = "West Europe"
}

resource "azurerm_storage_account" "media" {
  name                      = "acmemediaprod01"
  resource_group_name       = azurerm_resource_group.main.name
  location                  = azurerm_resource_group.main.location
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  allow_blob_public_access  = true
  min_tls_version           = "TLS1_0"
  shared_access_key_enabled = true

  tags = {
    environment = "prod"
  }
}

resource "azurerm_storage_container" "assets" {
  name                  = "assets"
  storage_account_name  = azurerm_storage_account.media.name
  container_access_type = "blob"
}
