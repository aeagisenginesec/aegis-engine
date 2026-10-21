resource "google_sql_database_instance" "main" {
  name = "db-153a0e"
  database_version = "POSTGRES_15"
  settings {
    tier = "db-f1-micro"
    backup_configuration { enabled = false }
    ip_configuration { ipv4_enabled = false }
  }
}

resource "google_sql_database_instance" "main" {
  name = "main-153a0e"
  database_version = "POSTGRES_15"
  region = "europe-west1"
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled = true
      authorized_networks { name = "world"  value = "0.0.0.0/0" }
    }
  }
}
