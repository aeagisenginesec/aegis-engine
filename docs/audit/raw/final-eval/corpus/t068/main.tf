terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-dev-778899"
  region  = "us-central1"
}

resource "google_compute_network" "default" {
  name                    = "default"
  auto_create_subnetworks = true
}

resource "google_compute_subnetwork" "no_logs" {
  name          = "default-subnet"
  network       = google_compute_network.default.id
  region        = "us-central1"
  ip_cidr_range = "10.128.0.0/20"
}

resource "google_compute_firewall" "allow_internal" {
  name    = "allow-internal"
  network = google_compute_network.default.id

  allow {
    protocol = "all"
  }

  source_ranges = ["10.128.0.0/9"]
}
