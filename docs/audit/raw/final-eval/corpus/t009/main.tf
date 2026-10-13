terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ap-southeast-1"
}

resource "aws_iam_role" "resizer" {
  name = "image-resizer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "resizer_wildcard" {
  name = "resizer-wildcard"
  role = aws_iam_role.resizer.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*", "dynamodb:*", "logs:*"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_lambda_function" "resizer" {
  function_name = "image-resizer"
  role          = aws_iam_role.resizer.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "resizer.zip"

  environment {
    variables = {
      API_KEY = "sk-live-9f8e7d6c5b4a3210"
      BUCKET  = aws_s3_bucket.uploads.id
    }
  }

  tags = {
    Name = "image-resizer"
  }
}

resource "aws_s3_bucket" "uploads" {
  bucket = "acme-uploads-44aa"

  tags = {
    Name = "uploads"
  }
}
