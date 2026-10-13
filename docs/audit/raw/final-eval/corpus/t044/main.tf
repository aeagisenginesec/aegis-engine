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
  name     = "rg-orders-prod"
  location = "North Europe"
}

resource "azurerm_cosmosdb_account" "orders" {
  name                = "acme-orders-cosmos"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  kind                = "GlobalDocumentDB"
  offer_type          = "Standard"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = "North Europe"
    failover_priority = 0
  }

  geo_location {
    location          = "West Europe"
    failover_priority = 1
  }

  ip_range_filter                 = "203.0.113.0/24"
  public_network_access_enabled   = true

  backup {
    type                = "Periodic"
    interval_in_minutes = 60
    retention_in_hours  = 168
  }
}

resource "azurerm_cosmosdb_sql_database" "orders" {
  name                = "ordersdb"
  resource_group_name = azurerm_resource_group.main.name
  account_name        = azurerm_cosmosdb_account.orders.name
  throughput          = 1000
}
