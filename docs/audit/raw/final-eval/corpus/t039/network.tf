resource "azurerm_resource_group" "main" {
  name     = "rg-${var.cluster_name}"
  location = var.location
}

resource "azurerm_virtual_network" "main" {
  name                = "vnet-${var.cluster_name}"
  address_space       = ["10.60.0.0/16"]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
}

resource "azurerm_subnet" "aks" {
  name                 = "snet-aks"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.60.1.0/24"]
}
