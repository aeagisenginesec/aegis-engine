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
  name     = "rg-payments-prod"
  location = "North Europe"
}

resource "azurerm_virtual_network" "main" {
  name                = "vnet-payments"
  address_space       = ["10.41.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_subnet" "vault" {
  name                 = "snet-vault"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.41.5.0/24"]
  service_endpoints    = ["Microsoft.KeyVault"]
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-payments"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

resource "azurerm_key_vault" "payments" {
  name                       = "acme-payments-kv"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = "00000000-0000-0000-0000-000000000000"
  sku_name                   = "premium"
  enable_rbac_authorization  = true
  soft_delete_retention_days = 90
  purge_protection_enabled   = true

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    virtual_network_subnet_ids = [azurerm_subnet.vault.id]
  }

  tags = {
    environment = "prod"
  }
}

resource "azurerm_role_assignment" "kv_admin" {
  scope                = azurerm_key_vault.payments.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = "11111111-2222-3333-4444-555555555555"
}

resource "azurerm_monitor_diagnostic_setting" "kv" {
  name                       = "kv-audit"
  target_resource_id         = azurerm_key_vault.payments.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "AuditEvent"
  }

  metric {
    category = "AllMetrics"
  }
}
