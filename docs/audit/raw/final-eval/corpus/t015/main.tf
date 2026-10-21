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

resource "aws_kms_key" "trail" {
  description         = "CloudTrail log encryption key"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "trail" {
  bucket = "acme-trail-logs-eu-51bd"

  tags = {
    Name = "trail-logs"
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail.arn}/*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "trail" {
  name = "/aws/cloudtrail/management-events"
}

resource "aws_cloudtrail" "main" {
  name                       = "org-trail"
  s3_bucket_name             = aws_s3_bucket.trail.id
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = aws_kms_key.trail.arn
  cloud_watch_logs_group_arn = aws_cloudwatch_log_group.trail.arn

  tags = {
    Name = "org-trail"
  }
}
