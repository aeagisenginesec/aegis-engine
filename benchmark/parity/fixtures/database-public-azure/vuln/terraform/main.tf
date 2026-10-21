resource "azurerm_resource_group" "rg" {
  name     = "parity-rg"
  location = "westeurope"
}

resource "azurerm_mssql_server" "db" {
  name                          = "parity-mssql"
  resource_group_name           = azurerm_resource_group.rg.name
  location                      = azurerm_resource_group.rg.location
  version                       = "12.0"
  administrator_login           = "dbadmin"
  administrator_login_password  = "Hardcoded123!"
  public_network_access_enabled = true
}

