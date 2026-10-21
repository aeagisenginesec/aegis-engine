variable "prefix" {
  type        = string
  description = "Resource name prefix"
}

variable "location" {
  type        = string
  description = "Azure region"
}

variable "allowed_subnet_id" {
  type        = string
  description = "Subnet allowed through the storage firewall"
}

variable "allowed_ips" {
  type        = list(string)
  description = "IP addresses allowed through the storage firewall"
}

variable "admin_object_ids" {
  type        = list(string)
  description = "Object IDs granted secret officer access on the vault"
}
