resource "azurerm_storage_account" "legacy" {
  name = "legacydfd1ff"
  resource_group_name = "rg-legacy"
  location = "westeurope"
  account_tier = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = false
  min_tls_version = "TLS1_0"
}
