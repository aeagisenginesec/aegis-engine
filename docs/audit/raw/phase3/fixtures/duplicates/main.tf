resource "azurerm_data_factory" "open" {
  name                   = "p3-adf"
  location               = "westeurope"
  public_network_enabled = true
}

resource "google_compute_instance" "serial" {
  name = "p3-inst"
  metadata = {
    serial-port-enable = "true"
  }
}
