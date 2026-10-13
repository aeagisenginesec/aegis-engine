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
  name     = "rg-shop-dev"
  location = "West Europe"
}

resource "azurerm_mssql_server" "shop" {
  name                         = "acme-shop-sql01"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  version                      = "12.0"
  administrator_login          = "sa"
  administrator_login_password = "P@ssw0rd1"
  minimum_tls_version          = "1.0"

  public_network_access_enabled = true
}

resource "azurerm_mssql_firewall_rule" "open" {
  name             = "allow-all"
  server_id        = azurerm_mssql_server.shop.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mssql_database" "shop" {
  name                                = "shopdb"
  server_id                           = azurerm_mssql_server.shop.id
  sku_name                            = "S0"
  transparent_data_encryption_enabled = false
}
