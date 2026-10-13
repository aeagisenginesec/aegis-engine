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
  name     = "rg-${var.prefix}"
  location = var.location
}

resource "azurerm_service_plan" "main" {
  name                = "asp-${var.prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Linux"
  sku_name            = "P1v2"
}

resource "azurerm_linux_web_app" "portal" {
  name                = "${var.prefix}-portal"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_service_plan.main.location
  service_plan_id     = azurerm_service_plan.main.id
  https_only          = true

  identity {
    type = "SystemAssigned"
  }

  site_config {
    minimum_tls_version = "1.2"
    ftps_state          = "FtpsOnly"
    always_on           = true
  }

  app_settings = {
    "DB_HOST"     = "${azurerm_mssql_server.db.name}.database.windows.net"
    "DB_NAME"     = azurerm_mssql_database.db.name
    "DB_USER"     = azurerm_mssql_server.db.administrator_login
    "DB_PASSWORD" = var.sql_admin_password
  }
}
