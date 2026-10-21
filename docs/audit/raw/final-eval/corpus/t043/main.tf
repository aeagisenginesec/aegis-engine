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
  name     = "rg-shop-prod"
  location = "West Europe"
}

resource "azurerm_cosmosdb_account" "shop" {
  name                = "acme-shop-cosmos"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  kind                = "Mongo"
  offer_type          = "Standard"

  consistency_policy {
    consistency_level = "Strong"
  }

  geo_location {
    location          = "West Europe"
    failover_priority = 0
  }

  public_network_access_enabled = true

  backup {
    type                = "Periodic"
    interval_in_minutes = 240
    retention_in_hours  = 8
  }

  capabilities {
    name = "EnableMongo"
  }
}
