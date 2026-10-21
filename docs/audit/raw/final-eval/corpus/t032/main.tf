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
  name     = "rg-backups-prod"
  location = "North Europe"
}

resource "azurerm_virtual_network" "main" {
  name                = "vnet-data"
  address_space       = ["10.40.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_subnet" "data" {
  name                 = "snet-data"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.40.1.0/24"]
  service_endpoints    = ["Microsoft.Storage"]
}

resource "azurerm_storage_account" "backups" {
  name                      = "acmebackups02"
  resource_group_name       = azurerm_resource_group.main.name
  location                  = azurerm_resource_group.main.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  allow_blob_public_access  = false
  min_tls_version           = "TLS1_2"
  shared_access_key_enabled = false

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [azurerm_subnet.data.id]
  }

  blob_properties {
    versioning_enabled = true
  }

  tags = {
    environment = "prod"
  }
}
