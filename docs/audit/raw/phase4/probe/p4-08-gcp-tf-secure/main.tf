resource "google_compute_firewall" "probeweb" {
  name    = "p4-probe-web-secure"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = ["10.128.0.0/9"]
}

resource "google_storage_bucket_iam_binding" "probedata" {
  bucket  = "p4-probe-bucket-002"
  role    = "roles/storage.objectViewer"
  members = ["serviceAccount:etl@p4-probe.iam.gserviceaccount.com"]
}
