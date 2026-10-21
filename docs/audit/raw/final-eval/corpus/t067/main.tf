terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-eu-445566"
  region  = "europe-west3"
}

resource "google_service_account" "nodes" {
  account_id   = "gke-nodes-min"
  display_name = "GKE minimal node SA"
}

resource "google_container_cluster" "main" {
  name                     = "workloads"
  location                 = "europe-west3"
  remove_default_node_pool = true
  initial_node_count       = 1

  workload_identity_config {
    workload_pool = "acme-eu-445566.svc.id.goog"
  }

  ip_allocation_policy {
  }
}

resource "google_container_node_pool" "main" {
  name       = "workload-pool"
  cluster    = google_container_cluster.main.name
  location   = "europe-west3"
  node_count = 3

  node_config {
    machine_type    = "e2-standard-4"
    service_account = google_service_account.nodes.email

    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring"
    ]
  }
}

resource "google_project_iam_member" "devs_admin" {
  project = "acme-eu-445566"
  role    = "roles/container.admin"
  member  = "group:devs@example.com"
}
