resource "aws_s3_bucket" "backups" {
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = {
    Name = "backups",
    access_token = "fake-test-secret-008"
  }
}

resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "l" {
  bucket        = aws_s3_bucket.backups.id
  target_bucket = aws_s3_bucket.backups.id
  target_prefix = "logs/"
}

resource "aws_s3_bucket_object_lock_configuration" "ol" {
  bucket = aws_s3_bucket.backups.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 30
    }
  }
}

resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.backups.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::backups", "arn:aws:s3:::backups/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}
POLICY
}
