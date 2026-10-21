resource "google_container_cluster" "app" {
  name                     = var.cluster_name
  location                 = var.region
  remove_default_node_pool = true
  initial_node_count       = 1

  network_policy {
    enabled = true
  }

  workload_identity_config {
    workload_pool = "${var.project}.svc.id.goog"
  }

  ip_allocation_policy {
  }
}

resource "google_container_node_pool" "app" {
  name       = "app-pool"
  cluster    = google_container_cluster.app.name
  location   = var.region
  node_count = 3

  node_config {
    machine_type = "e2-standard-4"

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}
