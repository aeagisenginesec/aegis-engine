terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "random_password" "sa" {
  length  = 24
  special = true
}

resource "azurerm_resource_group" "main" {
  name     = "rg-erp-prod"
  location = "North Europe"
}

resource "azurerm_storage_account" "audit" {
  name                      = "acmeerpaudit03"
  resource_group_name       = azurerm_resource_group.main.name
  location                  = azurerm_resource_group.main.location
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  allow_blob_public_access  = false
  min_tls_version           = "TLS1_2"

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }
}

resource "azurerm_mssql_server" "erp" {
  name                         = "acme-erp-sql01"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = random_password.sa.result
  minimum_tls_version          = "1.2"

  public_network_access_enabled = false

  azuread_administrator {
    login_username = "dba-team"
    object_id      = "22222222-3333-4444-5555-666666666666"
  }
}

resource "azurerm_mssql_database" "erp" {
  name                                = "erpdb"
  server_id                           = azurerm_mssql_server.erp.id
  sku_name                            = "S1"
  transparent_data_encryption_enabled = true
}

resource "azurerm_mssql_server_extended_auditing_policy" "erp" {
  server_id              = azurerm_mssql_server.erp.id
  storage_endpoint       = azurerm_storage_account.audit.primary_blob_endpoint
  storage_account_access_key = azurerm_storage_account.audit.primary_access_key
  retention_in_days      = 90
}
