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

variable "log_analytics_id" {
  type        = string
  description = "Log Analytics workspace ID for monitoring"
}

variable "tenant_id" {
  type        = string
  description = "Azure AD tenant ID"
}
