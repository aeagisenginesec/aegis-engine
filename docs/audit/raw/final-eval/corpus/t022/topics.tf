terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

resource "aws_kms_key" "sns" {
  description         = "${var.project} SNS encryption key"
  enable_key_rotation = true
}

resource "aws_sns_topic" "alerts" {
  name              = var.topic_name
  kms_master_key_id = aws_kms_key.sns.id

  tags = {
    Project = var.project
  }
}

resource "aws_sns_topic_policy" "tls_only" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnforceTLS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}
