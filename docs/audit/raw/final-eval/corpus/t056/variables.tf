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

variable "network" {
  type        = string
  description = "VPC network self link"
}

variable "subnetwork" {
  type        = string
  description = "Subnetwork self link"
}

variable "master_cidr" {
  type        = string
  description = "CIDR for the private control plane"
}
