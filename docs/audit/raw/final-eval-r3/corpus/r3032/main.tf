resource "google_storage_bucket" "assets" {
  name = "assets-b607b9"
  location = "US"
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.assets.name
  role = "roles/storage.objectViewer"
  member = "allUsers"
}
