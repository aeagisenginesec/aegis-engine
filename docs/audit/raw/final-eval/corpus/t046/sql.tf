resource "azurerm_mssql_server" "db" {
  name                         = "${var.prefix}-sql01"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  version                      = "12.0"
  administrator_login          = "dbadmin"
  administrator_login_password = var.sql_admin_password
  minimum_tls_version          = "1.2"

  public_network_access_enabled = true
}

resource "azurerm_mssql_firewall_rule" "open" {
  name             = "allow-all"
  server_id        = azurerm_mssql_server.db.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "255.255.255.255"
}

resource "azurerm_mssql_firewall_rule" "office" {
  name             = "allow-office"
  server_id        = azurerm_mssql_server.db.id
  start_ip_address = var.office_ip
  end_ip_address   = var.office_ip
}

resource "azurerm_mssql_database" "db" {
  name                                = "portaldb"
  server_id                           = azurerm_mssql_server.db.id
  sku_name                            = "S1"
  transparent_data_encryption_enabled = true
}
