terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-legacy-771204"
  region  = "us-central1"
}

resource "google_compute_instance" "legacy_app" {
  name         = "legacy-app-01"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

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

  can_ip_forward = true

  service_account {
    scopes = ["cloud-platform"]
  }
}

resource "google_compute_instance" "legacy_batch" {
  name         = "legacy-batch-01"
  machine_type = "e2-standard-2"
  zone         = "us-central1-b"

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

  can_ip_forward = true

  service_account {
    scopes = ["cloud-platform"]
  }
}
