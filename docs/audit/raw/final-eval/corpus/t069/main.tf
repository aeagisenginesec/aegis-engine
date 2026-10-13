terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-crm-334455"
  region  = "europe-west1"
}

resource "google_sql_database_instance" "crm" {
  name             = "crm-postgres"
  database_version = "POSTGRES_15"
  region           = "europe-west1"

  settings {
    tier = "db-custom-2-7680"

    ip_configuration {
      ipv4_enabled = true
      require_ssl  = true

      authorized_networks {
        name  = "office"
        value = "203.0.113.0/24"
      }
    }

    backup_configuration {
      enabled = true
    }
  }

  deletion_protection = false
}

resource "google_sql_database" "crm" {
  name     = "crmdb"
  instance = google_sql_database_instance.crm.name
}
