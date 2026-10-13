terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-erp-271828"
  region  = "europe-west1"
}

resource "google_compute_network" "private" {
  name                    = "db-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_global_address" "psa" {
  name          = "psa-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.private.id
}

resource "google_service_networking_connection" "psa" {
  network                 = google_compute_network.private.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.psa.name]
}

resource "google_kms_key_ring" "sql" {
  name     = "sql-ring"
  location = "europe-west1"
}

resource "google_kms_crypto_key" "sql" {
  name            = "sql-key"
  key_ring        = google_kms_key_ring.sql.id
  rotation_period = "7776000s"
}

resource "google_sql_database_instance" "erp" {
  name             = "erp-postgres"
  database_version = "POSTGRES_15"
  region           = "europe-west1"

  settings {
    tier = "db-custom-4-15360"

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.private.id
      require_ssl     = true
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
  }

  encryption_key_name = google_kms_crypto_key.sql.id
  deletion_protection = true

  depends_on = [google_service_networking_connection.psa]
}
