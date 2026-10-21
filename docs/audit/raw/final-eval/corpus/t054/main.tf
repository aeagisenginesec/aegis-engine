terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-app-883415"
  region  = "europe-west1"
}

resource "google_compute_instance" "app" {
  name         = "app-web-01"
  machine_type = "e2-standard-2"
  zone         = "europe-west1-b"

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  network_interface {
    network = "default"

    access_config {
    }
  }

  service_account {
    scopes = ["logging-write", "monitoring-write"]
  }

  metadata = {
    enable-oslogin = "TRUE"
  }
}

resource "google_compute_instance" "worker" {
  name         = "app-worker-01"
  machine_type = "e2-standard-2"
  zone         = "europe-west1-b"

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  network_interface {
    network = "default"
  }

  service_account {
    scopes = ["logging-write", "monitoring-write"]
  }

  metadata = {
    enable-oslogin = "TRUE"
  }
}
