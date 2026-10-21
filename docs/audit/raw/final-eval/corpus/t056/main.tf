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
  network                  = var.network
  subnetwork               = var.subnetwork
  remove_default_node_pool = true
  initial_node_count       = 1

  release_channel {
    channel = "REGULAR"
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = var.master_cidr
  }

  master_authorized_networks_config {
  }

  network_policy {
    enabled = true
  }

  workload_identity_config {
    workload_pool = "${var.project}.svc.id.goog"
  }

  binary_authorization {
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }

  ip_allocation_policy {
  }
}
