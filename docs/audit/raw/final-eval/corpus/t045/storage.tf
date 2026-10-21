resource "azurerm_storage_account" "data" {
  name                      = "${var.prefix}data01"
  resource_group_name       = azurerm_resource_group.main.name
  location                  = azurerm_resource_group.main.location
  account_tier              = "Standard"
  account_replication_type  = "GRS"
  allow_blob_public_access  = false
  min_tls_version           = "TLS1_2"
  shared_access_key_enabled = false

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = [var.allowed_subnet_id]
    ip_rules                   = var.allowed_ips
  }

  blob_properties {
    versioning_enabled = true
  }
}
