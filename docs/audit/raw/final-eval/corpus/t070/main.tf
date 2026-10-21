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

module "network" {
  source       = "./modules/network"
  network_name = "${var.cluster_name}-net"
  project      = var.project
  region       = var.region
}

resource "google_container_cluster" "main" {
  name                     = var.cluster_name
  location                 = var.region
  network                  = module.network.network_id
  subnetwork               = module.network.subnetwork_id
  remove_default_node_pool = true
  initial_node_count       = 1

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  workload_identity_config {
    workload_pool = "${var.project}.svc.id.goog"
  }

  ip_allocation_policy {
  }
}

resource "google_container_node_pool" "pools" {
  for_each   = var.node_pools
  name       = each.key
  cluster    = google_container_cluster.main.name
  location   = var.region
  node_count = each.value.node_count

  node_config {
    machine_type = each.value.machine_type

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}
