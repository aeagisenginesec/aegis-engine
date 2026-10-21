variable "project" {
  type        = string
  description = "GCP project ID"
}

variable "network_name" {
  type        = string
  description = "VPC network name"
}

variable "rules" {
  type = map(object({
    description = string
    direction   = string
    protocol    = string
    ports       = list(string)
    ranges      = list(string)
    target_tags = list(string)
  }))
  description = "Firewall rules to manage"
}
