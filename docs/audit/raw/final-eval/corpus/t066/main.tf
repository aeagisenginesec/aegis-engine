terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-data-112233"
  region  = "europe-west1"
}

resource "google_storage_bucket" "logs" {
  name                        = "acme-pipeline-logs"
  location                    = "EU"
  uniform_bucket_level_access = true

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}

resource "google_storage_bucket_iam_binding" "contractors" {
  bucket  = google_storage_bucket.logs.name
  role    = "roles/storage.objectViewer"
  members = ["group:contractors@example.com"]
}
