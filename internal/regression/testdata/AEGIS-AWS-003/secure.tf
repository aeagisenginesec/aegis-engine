resource "aws_s3_bucket" "safe" {
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_policy" "safe" {
  bucket = aws_s3_bucket.safe.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::safe/*"
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::safe", "arn:aws:s3:::safe/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}
POLICY
}

resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.safe.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "l" {
  bucket        = aws_s3_bucket.safe.id
  target_bucket = aws_s3_bucket.safe.id
  target_prefix = "logs/"
}

resource "aws_s3_bucket_object_lock_configuration" "ol" {
  bucket = aws_s3_bucket.safe.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 30
    }
  }
}

resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.safe.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
