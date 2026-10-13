resource "google_storage_bucket" "assets" {
  name = "assets-6955e7"
  location = "US"
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.assets.name
  role = "roles/storage.objectViewer"
  member = "allUsers"
}

resource "aws_security_group" "db" {
  name = "db-6955e7"
  ingress {
    from_port = 5432
    to_port = 5432
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
