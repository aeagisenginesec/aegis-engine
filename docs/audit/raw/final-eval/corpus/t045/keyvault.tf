data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "app" {
  name                       = "${var.prefix}-kv"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 90
  purge_protection_enabled   = false

  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }

  dynamic "access_policy" {
    for_each = var.admin_object_ids

    content {
      tenant_id = data.azurerm_client_config.current.tenant_id
      object_id = access_policy.value

      secret_permissions = [
        "Get", "Set", "Delete", "List"
      ]
    }
  }
}
