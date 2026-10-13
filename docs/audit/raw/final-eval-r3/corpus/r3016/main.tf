resource "azurerm_storage_account" "legacy" {
  name = "legacy83f993"
  resource_group_name = "rg-legacy"
  location = "westeurope"
  account_tier = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = false
  min_tls_version = "TLS1_0"
}

resource "aws_security_group" "bastion" {
  name = "bastion-83f993"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
