terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_ecr_repository" "api" {
  name                 = "payments-api"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "payments-api"
  }
}

resource "aws_iam_role" "staging_cluster" {
  name = "staging-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "eks.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "staging_cluster" {
  role       = aws_iam_role.staging_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "staging" {
  name     = "staging"
  role_arn = aws_iam_role.staging_cluster.arn
  version  = "1.29"

  vpc_config {
    subnet_ids              = ["subnet-s1", "subnet-s2"]
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }

  enabled_cluster_log_types = ["api", "audit"]

  tags = {
    Name = "staging"
  }
}
