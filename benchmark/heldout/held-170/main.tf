resource "aws_s3_bucket" "c170" {
  bucket = "clean-170-assets"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "c170" {
  bucket = aws_s3_bucket.c170.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "c170" {
  bucket = aws_s3_bucket.c170.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "c170" {
  bucket = aws_s3_bucket.c170.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "c170" {
  bucket = aws_s3_bucket.c170.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "EnforceTLS"
      Effect = "Deny"
      Principal = "*"
      Action = "s3:*"
      Resource = [
        aws_s3_bucket.c170.arn,
        "${aws_s3_bucket.c170.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

resource "aws_s3_bucket_logging" "c170" {
  bucket = aws_s3_bucket.c170.id
  target_bucket = aws_s3_bucket.c170_logs.id
  target_prefix = "log/"
}

resource "aws_s3_bucket" "c170_logs" {
  bucket = "clean-170-assets-logs"
}

resource "aws_s3_bucket_lifecycle_configuration" "c170" {
  bucket = aws_s3_bucket.c170.id
  rule {
    id = "expire-old"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}

