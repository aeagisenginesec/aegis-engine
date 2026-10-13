terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_kms_key" "data" {
  description             = "Application data key"
  enable_key_rotation     = false
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "OpenDecrypt"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "app-data-key"
  }
}

resource "aws_kms_alias" "data" {
  name          = "alias/app-data"
  target_key_id = aws_kms_key.data.key_id
}
