variable "prefix" {
  type        = string
  description = "Resource name prefix"
}

variable "location" {
  type        = string
  description = "Azure region"
}

variable "node_count" {
  type        = number
  description = "AKS node count"
}
