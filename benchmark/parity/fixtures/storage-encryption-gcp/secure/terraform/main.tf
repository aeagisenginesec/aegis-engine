resource "google_storage_bucket" "b" {
  name     = "parity-enc-bucket"
  location = "EU"

  encryption {
    default_kms_key_name = "projects/p/locations/global/keyRings/r/cryptoKeys/k"
  }
}
