variable "cluster_name" {
  type        = string
  description = "AKS cluster name"
}

variable "location" {
  type        = string
  description = "Azure region"
}

variable "dns_prefix" {
  type        = string
  description = "DNS prefix for the cluster"
}

variable "node_count" {
  type        = number
  description = "Default node pool size"
}

variable "vm_size" {
  type        = string
  description = "VM size for system nodes"
}
