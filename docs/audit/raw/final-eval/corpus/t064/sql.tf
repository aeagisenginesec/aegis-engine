terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project
  region  = var.region
}

resource "google_compute_network" "db" {
  name                    = "${var.cluster_name}-db-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_global_address" "psa" {
  name          = "${var.cluster_name}-psa"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.db.id
}

resource "google_service_networking_connection" "psa" {
  network                 = google_compute_network.db.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.psa.name]
}

resource "google_sql_database_instance" "app" {
  name             = "${var.cluster_name}-db"
  database_version = "POSTGRES_15"
  region           = var.region

  settings {
    tier = var.db_tier

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.db.id
      require_ssl     = true
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
    }
  }

  deletion_protection = true

  depends_on = [google_service_networking_connection.psa]
}
