variable "region" {
  type        = string
  description = "AWS region"
}

variable "ami_owner" {
  type        = string
  description = "AMI owner account ID"
}

variable "instance_type" {
  type        = string
  description = "EC2 instance type"
}

variable "key_name" {
  type        = string
  description = "SSH key pair name"
}

variable "allowed_ssh_cidr" {
  type        = string
  description = "CIDR allowed SSH access"
}

variable "app_bucket" {
  type        = string
  description = "Application S3 bucket name"
}
