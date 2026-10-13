variable "network_name" {
  type        = string
  description = "VPC network name"
}

variable "project" {
  type        = string
  description = "GCP project ID"
}

variable "region" {
  type        = string
  description = "GCP region"
}

resource "google_compute_network" "main" {
  name                    = var.network_name
  project                 = var.project
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "main" {
  name          = "${var.network_name}-subnet"
  project       = var.project
  region        = var.region
  network       = google_compute_network.main.id
  ip_cidr_range = "10.60.0.0/16"
}

output "network_id" {
  value = google_compute_network.main.id
}

output "subnetwork_id" {
  value = google_compute_subnetwork.main.id
}
