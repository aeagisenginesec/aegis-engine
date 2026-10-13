terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "acme-prod-418201"
  region  = "us-central1"
}

resource "google_project_iam_custom_role" "logviewer" {
  role_id     = "logViewerPlus"
  title       = "Log Viewer Plus"
  description = "Read access to logs and monitoring"
  permissions = [
    "logging.logEntries.list",
    "logging.logs.list",
    "monitoring.timeSeries.list"
  ]
}

resource "google_project_iam_member" "analyst" {
  project = "acme-prod-418201"
  role    = google_project_iam_custom_role.logviewer.id
  member  = "user:analyst@example.com"
}

resource "google_project_iam_member" "dev_editor" {
  project = "acme-prod-418201"
  role    = "roles/editor"
  member  = "user:dev@example.com"
}

resource "google_service_account" "etl" {
  account_id   = "etl-job"
  display_name = "Nightly ETL job"
}
