variable "service_token" {
  type      = string
  sensitive = true
}

output "service_token" {
  value     = var.service_token
  sensitive = false
}
