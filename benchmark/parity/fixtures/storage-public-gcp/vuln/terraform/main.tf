resource "google_storage_bucket" "b" {
  name     = "parity-public-bucket"
  location = "EU"
}

resource "google_storage_bucket_iam_binding" "pub" {
  bucket  = google_storage_bucket.b.name
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}
