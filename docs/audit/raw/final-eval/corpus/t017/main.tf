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

resource "aws_kms_key" "payments" {
  description             = "Payments encryption key"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPaymentsRole"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::123456789012:role/payments-service" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "payments-key"
  }
}

resource "aws_kms_alias" "payments" {
  name          = "alias/payments"
  target_key_id = aws_kms_key.payments.key_id
}
