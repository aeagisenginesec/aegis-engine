resource "google_compute_instance" "etl" {
  name         = var.instance_name
  machine_type = "e2-standard-4"
  zone         = "${var.region}-a"

  boot_disk {
    initialize_params {
      image = data.google_compute_image.ubuntu.self_link
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
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin = "TRUE"
  }
}
