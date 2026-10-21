# === AWS (12 resources) ===
resource "aws_s3_bucket" "pub" { bucket = "c1" acl = "public-read" }
resource "aws_s3_bucket" "priv" { bucket = "c2" }
resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "closed" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
resource "aws_db_instance" "pubdb" {
  engine = "postgres" instance_class = "db.t3.micro"
  publicly_accessible = true skip_final_snapshot = true
}
resource "aws_db_instance" "privdb" {
  engine = "postgres" instance_class = "db.t3.micro"
  publicly_accessible = false storage_encrypted = true deletion_protection = true
}
resource "aws_iam_policy" "admin" {
  policy = jsonencode({ Statement = [{ Effect = "Allow" Action = "*" Resource = "*" }] })
}
resource "aws_iam_policy" "readonly" {
  policy = jsonencode({ Statement = [{ Effect = "Allow" Action = ["s3:GetObject"] Resource = "arn:aws:s3:::c2/*" }] })
}
resource "aws_ebs_volume" "unenc" { availability_zone = "us-east-1a" size = 10 }
resource "aws_ebs_volume" "enc" { availability_zone = "us-east-1a" size = 10 encrypted = true }
resource "aws_kms_key" "norot" { deletion_window_in_days = 7 }
resource "aws_cloudtrail" "single" { name = "t1" s3_bucket_name = "c2" }

# === Azure (8 resources) ===
resource "azurerm_storage_account" "pubst" {
  name = "stpub" resource_group_name = "rg" location = "westeurope"
  account_tier = "Standard" account_replication_type = "LRS"
  allow_blob_public_access = true min_tls_version = "TLS1_0"
}
resource "azurerm_storage_account" "secst" {
  name = "stsec" resource_group_name = "rg" location = "westeurope"
  account_tier = "Standard" account_replication_type = "GRS"
  allow_blob_public_access = false min_tls_version = "TLS1_2"
}
resource "azurerm_key_vault" "nopurge" {
  name = "kv1" resource_group_name = "rg" location = "westeurope" sku_name = "standard"
  purge_protection_enabled = false
}
resource "azurerm_key_vault" "purged" {
  name = "kv2" resource_group_name = "rg" location = "westeurope" sku_name = "standard"
  purge_protection_enabled = true soft_delete_retention_days = 90
}
resource "azurerm_sql_server" "weak" {
  name = "sql1" resource_group_name = "rg" location = "westeurope" version = "12.0"
  administrator_login = "a" administrator_login_password = "Password123!"
}
resource "azurerm_network_security_group" "opennsg" {
  name = "nsg1" resource_group_name = "rg" location = "westeurope"
  security_rule {
    name                       = "r1"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
resource "azurerm_network_security_group" "closednsg" {
  name = "nsg2" resource_group_name = "rg" location = "westeurope"
  security_rule {
    name                       = "r1"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.0.0.0/8"
    destination_address_prefix = "*"
  }
}

# === GCP (8 resources) ===
resource "google_storage_bucket" "pubb" { name = "gb1" location = "EU" }
resource "google_storage_bucket" "secb" {
  name = "gb2"
  location = "EU"
  uniform_bucket_level_access = true
  versioning {
    enabled = true
  }
}
resource "google_compute_firewall" "openfw" {
  name = "fw1" network = "default"
  allow { protocol = "tcp" ports = ["22"] }
  source_ranges = ["0.0.0.0/0"]
}
resource "google_compute_firewall" "closedfw" {
  name = "fw2" network = "default"
  allow { protocol = "tcp" ports = ["22"] }
  source_ranges = ["10.0.0.0/8"]
}
resource "google_sql_database_instance" "nolog" {
  name = "db1" database_version = "POSTGRES_14"
  settings { tier = "db-f1-micro" }
}
resource "google_compute_instance" "pubvm" {
  name = "vm1" machine_type = "e2-micro" zone = "europe-west1-b"
  boot_disk {
    initialize_params {
      image = "debian-11"
    }
  }
  network_interface {
    network = "default"
    access_config {}
  }
  metadata = {
    enable-oslogin = "FALSE"
  }
}
resource "google_compute_instance" "privvm" {
  name = "vm2" machine_type = "e2-micro" zone = "europe-west1-b"
  boot_disk {
    initialize_params {
      image = "debian-11"
    }
  }
  network_interface { network = "default" }
  metadata = {
    enable-oslogin = "TRUE"
  }
}
