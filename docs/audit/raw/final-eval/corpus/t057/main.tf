terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-shop-314159"
  region  = "us-central1"
}

resource "google_sql_database_instance" "shop" {
  name             = "shop-postgres"
  database_version = "POSTGRES_15"
  region           = "us-central1"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "anywhere"
        value = "0.0.0.0/0"
      }
    }

    backup_configuration {
      enabled = false
    }
  }

  deletion_protection = false
}

resource "google_sql_user" "app" {
  name     = "app"
  instance = google_sql_database_instance.shop.name
  password = "shopapp123"
}
