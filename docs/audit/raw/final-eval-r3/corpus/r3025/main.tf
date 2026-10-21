resource "azurerm_network_security_group" "web" {
  name = "web-8ae4c4"
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

resource "aws_db_instance" "app" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  identifier = "app-8ae4c4"
  allocated_storage = 20
  storage_encrypted = true
  publicly_accessible = true
  username = "appadmin"
  password = "Str0ng-8ae4c4-Db!"
  backup_retention_period = 7
  skip_final_snapshot = true
}
