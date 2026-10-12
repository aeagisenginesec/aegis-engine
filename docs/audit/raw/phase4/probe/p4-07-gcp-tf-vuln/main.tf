resource "google_compute_firewall" "probeweb" {
  name    = "p4-probe-web"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_storage_bucket_iam_binding" "probedata" {
  bucket  = "p4-probe-bucket-001"
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}
