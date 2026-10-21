variable "project" {
  type        = string
  description = "GCP project ID"
}

variable "region" {
  type        = string
  description = "GCP region"
}

variable "db_tier" {
  type        = string
  description = "Cloud SQL machine tier"
}

variable "cluster_name" {
  type        = string
  description = "GKE cluster name"
}
