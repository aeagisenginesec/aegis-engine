terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project
  region  = "europe-west1"
}

resource "google_compute_network" "main" {
  name                    = var.network_name
  auto_create_subnetworks = false
}

resource "google_compute_firewall" "managed" {
  for_each    = var.rules
  name        = each.key
  network     = google_compute_network.main.id
  description = each.value.description
  direction   = each.value.direction

  dynamic "allow" {
    for_each = [each.value]

    content {
      protocol = allow.value.protocol
      ports    = allow.value.ports
    }
  }

  source_ranges      = each.value.direction == "INGRESS" ? each.value.ranges : null
  destination_ranges = each.value.direction == "EGRESS" ? each.value.ranges : null
  target_tags        = each.value.target_tags
}

resource "google_compute_firewall" "legacy_alt_http" {
  name        = "legacy-allow-alt-http"
  network     = google_compute_network.main.id
  description = "Legacy rule retained for the old monitoring agent"
  direction   = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["legacy-agent"]
}
