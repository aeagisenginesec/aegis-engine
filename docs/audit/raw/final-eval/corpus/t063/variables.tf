variable "project" {
  type        = string
  description = "GCP project ID"
}

variable "region" {
  type        = string
  description = "GCP region"
}

variable "bucket_name" {
  type        = string
  description = "Storage bucket name"
}

variable "instance_name" {
  type        = string
  description = "Compute instance name"
}
