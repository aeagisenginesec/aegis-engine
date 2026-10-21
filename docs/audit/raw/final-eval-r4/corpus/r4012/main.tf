resource "azurerm_network_security_group" "web" {
  name = "web-33148d"
  location = "westeurope"
  resource_group_name = "rg-web"
  security_rule {
    name = "ssh"
    priority = 100
    direction = "Inbound"
    access = "Allow"
    protocol = "Tcp"
    source_port_range = "*"
    destination_port_range = "22"
    source_address_prefix = "*"
    destination_address_prefix = "*"
  }
}
