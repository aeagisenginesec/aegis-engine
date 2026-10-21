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

variable "subnet_ids" {
  type        = list(string)
  description = "Subnets for the control plane and worker nodes"
}

variable "node_instance_types" {
  type        = list(string)
  description = "EC2 instance types for worker nodes"
}

variable "desired_nodes" {
  type        = number
  description = "Desired worker node count"
}
