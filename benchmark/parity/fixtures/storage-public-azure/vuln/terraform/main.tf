resource "azurerm_resource_group" "rg" {
  name     = "parity-rg"
  location = "westeurope"
}

resource "azurerm_storage_account" "st" {
  name                     = "paritypublicst"
  resource_group_name      = azurerm_resource_group.rg.name
  location                 = azurerm_resource_group.rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = true
}
