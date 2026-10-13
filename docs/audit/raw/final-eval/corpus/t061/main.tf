terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-dev-990211"
  region  = "us-central1"
}

resource "google_compute_firewall" "allow_all_ingress" {
  name    = "allow-all-ingress"
  network = "default"

  allow {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_compute_firewall" "allow_all_egress" {
  name      = "allow-all-egress"
  network   = "default"
  direction = "EGRESS"

  allow {
    protocol = "all"
  }

  destination_ranges = ["0.0.0.0/0"]
}
