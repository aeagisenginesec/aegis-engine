variable "prefix" {
  type        = string
  description = "Resource name prefix"
}

variable "location" {
  type        = string
  description = "Azure region"
}

variable "sql_admin_password" {
  type        = string
  sensitive   = true
  description = "SQL administrator password"
}

variable "office_ip" {
  type        = string
  description = "Office public IP for admin access"
}
