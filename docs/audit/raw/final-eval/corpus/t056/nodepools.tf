resource "google_service_account" "nodes" {
  account_id   = "gke-nodes"
  display_name = "GKE node service account"
}

resource "google_container_node_pool" "secure" {
  name       = "secure-pool"
  cluster    = google_container_cluster.main.name
  location   = var.region
  node_count = 3

  node_config {
    machine_type    = "e2-standard-4"
    service_account = google_service_account.nodes.email

    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring"
    ]

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}
