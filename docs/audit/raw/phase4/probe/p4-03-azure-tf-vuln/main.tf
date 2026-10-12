resource "azurerm_storage_account" "probestore" {
  name                      = "p4probevuln001"
  resource_group_name       = "p4-probe-rg"
  location                  = "westeurope"
  account_tier              = "Standard"
  account_replication_type  = "LRS"

  public_network_access_enabled = true
  allow_blob_public_access      = true
}
