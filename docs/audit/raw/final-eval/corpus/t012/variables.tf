variable "cluster_name" {
  type        = string
  description = "Name of the EKS cluster"
}

variable "region" {
  type        = string
  description = "AWS region for the cluster"
}

variable "vpc_id" {
  type        = string
  description = "VPC hosting the cluster"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnets for the control plane and nodes"
}

variable "kms_key_arn" {
  type        = string
  description = "KMS key ARN for envelope encryption of secrets"
}

variable "cluster_log_types" {
  type        = list(string)
  description = "Control plane log types to enable"
}
