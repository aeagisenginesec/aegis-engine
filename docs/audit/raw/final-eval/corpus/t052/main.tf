terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-finance-552310"
  region  = "us-central1"
}

resource "google_kms_key_ring" "data" {
  name     = "data-ring"
  location = "us-central1"
}

resource "google_kms_crypto_key" "bucket" {
  name            = "bucket-key"
  key_ring        = google_kms_key_ring.data.id
  rotation_period = "7776000s"
}

resource "google_storage_bucket" "finance" {
  name                        = "acme-finance-docs"
  location                    = "US"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.bucket.id
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 3
    }
    action {
      type = "Delete"
    }
  }
}
