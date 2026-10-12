# AEGIS-AZURE-049: MSSQL database without TDE (explicit false)
resource "azurerm_mssql_database" "no_tde" {
  name                                = "p3-db"
  transparent_data_encryption_enabled = false
}

# AEGIS-AZURE-049 negative: TDE enabled
resource "azurerm_mssql_database" "tde" {
  name                                = "p3-db-ok"
  transparent_data_encryption_enabled = true
}

# AEGIS-AZURE-098: MariaDB server without SSL enforcement (explicit false)
resource "azurerm_mariadb_server" "no_ssl" {
  name                    = "p3-maria"
  ssl_enforcement_enabled = false
}

# AEGIS-AZURE-098 negative: SSL enforced
resource "azurerm_mariadb_server" "ssl" {
  name                    = "p3-maria-ok"
  ssl_enforcement_enabled = true
}
