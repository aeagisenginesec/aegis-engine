resource "google_sql_database_instance" "db" {
  name             = "parity-db"
  database_version = "POSTGRES_15"
  region           = "europe-west1"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true

      authorized_networks {
        name  = "open-to-world"
        value = "0.0.0.0/0"
      }
    }
  }
}
