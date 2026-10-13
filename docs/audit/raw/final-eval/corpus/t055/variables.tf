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

variable "node_count" {
  type        = number
  description = "Node pool size"
}

variable "machine_type" {
  type        = string
  description = "Node machine type"
}
