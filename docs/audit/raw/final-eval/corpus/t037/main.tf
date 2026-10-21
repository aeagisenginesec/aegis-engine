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

resource "azurerm_service_plan" "main" {
  name                = "asp-shop-dev"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  os_type             = "Windows"
  sku_name            = "B1"
}

resource "azurerm_windows_web_app" "shop" {
  name                = "acme-shop-web"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_service_plan.main.location
  service_plan_id     = azurerm_service_plan.main.id
  https_only          = false

  site_config {
    minimum_tls_version = "1.0"
    ftps_state          = "AllAllowed"
    always_on           = false
  }

  app_settings = {
    "DB_CONNECTION" = "Server=acme-shop-sql01.database.windows.net;Database=shopdb;User=sa;Password=P@ssw0rd1;"
    "APPINSIGHTS_KEY" = "00000000-0000-0000-0000-000000000000"
  }
}
