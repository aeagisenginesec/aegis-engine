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

resource "google_service_account" "ci" {
  account_id   = "ci-runner"
  display_name = "CI runner"
}

resource "google_project_iam_binding" "ci_owner" {
  project = "acme-prod-418201"
  role    = "roles/owner"
  members = [
    "serviceAccount:${google_service_account.ci.email}"
  ]
}

resource "google_project_iam_member" "devs_editor" {
  project = "acme-prod-418201"
  role    = "roles/editor"
  member  = "group:devs@example.com"
}

resource "google_service_account_key" "ci" {
  service_account_id = google_service_account.ci.name
}
