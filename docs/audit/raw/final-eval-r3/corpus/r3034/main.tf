resource "google_compute_instance" "nat" {
  name = "nat-8e725a"
  machine_type = "e2-medium"
  zone = "europe-west1-b"
  can_ip_forward = true
  boot_disk {
    initialize_params { image = "debian-cloud/debian-12" }
  }
  network_interface { network = "default"
    access_config {}
  }
}
