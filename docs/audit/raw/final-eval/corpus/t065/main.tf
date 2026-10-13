terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-dev-665432"
  region  = "asia-southeast1"
}

resource "google_compute_instance" "dev" {
  name         = "dev-vm-01"
  machine_type = "e2-medium"
  zone         = "asia-southeast1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"

    access_config {
    }
  }

  metadata = {
    ssh-keys = "dev:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7 demo-key dev@laptop"
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}

resource "google_compute_instance" "qa" {
  name         = "qa-vm-01"
  machine_type = "e2-medium"
  zone         = "asia-southeast1-b"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"

    access_config {
    }
  }

  metadata = {
    ssh-keys = "qa:ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD2 demo-key qa@laptop"
  }

  service_account {
    scopes = ["cloud-platform"]
  }
}
