variable "project" {
  type        = string
  description = "GCP project ID"
}

variable "region" {
  type        = string
  description = "GCP region"
}

variable "cluster_name" {
  type        = string
  description = "GKE cluster name"
}

variable "node_pools" {
  type = map(object({
    machine_type = string
    node_count   = number
  }))
  description = "Node pool definitions"
}

variable "db_tier" {
  type        = string
  description = "Cloud SQL machine tier"
}
