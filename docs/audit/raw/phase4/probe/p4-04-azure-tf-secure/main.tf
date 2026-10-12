resource "azurerm_storage_account" "probestore" {
  name                      = "p4probesecure01"
  resource_group_name       = "p4-probe-rg"
  location                  = "westeurope"
  account_tier              = "Standard"
  account_replication_type  = "LRS"

  public_network_access_enabled = false
  allow_blob_public_access      = false
  min_tls_version               = "TLS1_2"
}
