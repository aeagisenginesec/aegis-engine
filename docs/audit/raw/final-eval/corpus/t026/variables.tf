variable "region" {
  type        = string
  description = "AWS region"
}

variable "db_password" {
  type        = string
  sensitive   = true
  description = "Master password for the database"
}

variable "bucket_suffix" {
  type        = string
  description = "Suffix for the export bucket name"
}

variable "instance_class" {
  type        = string
  description = "RDS instance class"
}
