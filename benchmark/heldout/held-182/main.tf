resource "aws_s3_bucket" "c182" {
  bucket = "clean-182-assets"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "c182" {
  bucket = aws_s3_bucket.c182.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "c182" {
  bucket = aws_s3_bucket.c182.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "c182" {
  bucket = aws_s3_bucket.c182.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "c182" {
  bucket = aws_s3_bucket.c182.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "EnforceTLS"
      Effect = "Deny"
      Principal = "*"
      Action = "s3:*"
      Resource = [
        aws_s3_bucket.c182.arn,
        "${aws_s3_bucket.c182.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

resource "aws_s3_bucket_logging" "c182" {
  bucket = aws_s3_bucket.c182.id
  target_bucket = aws_s3_bucket.c182_logs.id
  target_prefix = "log/"
}

resource "aws_s3_bucket" "c182_logs" {
  bucket = "clean-182-assets-logs"
}

resource "aws_s3_bucket_lifecycle_configuration" "c182" {
  bucket = aws_s3_bucket.c182.id
  rule {
    id = "expire-old"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}

