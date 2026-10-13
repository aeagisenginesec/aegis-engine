resource "google_container_node_pool" "main" {
  name       = "default-pool"
  cluster    = google_container_cluster.main.name
  location   = var.region
  node_count = var.node_count

  node_config {
    machine_type    = var.machine_type
    service_account = "default"
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}
