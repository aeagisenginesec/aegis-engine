terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

resource "aws_sns_topic" "orders" {
  name                        = "orders.fifo"
  fifo_topic                  = true
  content_based_deduplication = true

  tags = {
    Name = "orders-fifo"
  }
}

resource "aws_sns_topic_policy" "open" {
  arn = aws_sns_topic.orders.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAnyPublisher"
        Effect    = "Allow"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.orders.arn
      }
    ]
  })
}

resource "aws_sqs_queue" "orders" {
  name                        = "orders.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  kms_master_key_id           = "alias/aws/sqs"

  tags = {
    Name = "orders-fifo"
  }
}
