resource "aws_kms_key" "data" {
  description = "data-key-bb8a0f"
  enable_key_rotation = false
}

resource "aws_s3_bucket" "vault" {
  bucket = "vault-bb8a0f"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault" {
  bucket = aws_s3_bucket.vault.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "google_compute_instance" "nat" {
  name = "nat-bb8a0f"
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
