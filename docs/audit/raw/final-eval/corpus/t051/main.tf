terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-marketing-418201"
  region  = "us-central1"
}

resource "google_storage_bucket" "assets" {
  name     = "acme-marketing-assets"
  location = "US"
}

resource "google_storage_bucket_iam_binding" "public" {
  bucket  = google_storage_bucket.assets.name
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}
