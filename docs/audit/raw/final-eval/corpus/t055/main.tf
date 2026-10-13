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

resource "google_container_cluster" "main" {
  name                     = var.cluster_name
  location                 = var.region
  remove_default_node_pool = true
  initial_node_count       = 1

  master_auth {
    username = "admin"
    password = "ChangeMe123!"

    client_certificate_config {
      issue_client_certificate = true
    }
  }

  ip_allocation_policy {
  }
}
