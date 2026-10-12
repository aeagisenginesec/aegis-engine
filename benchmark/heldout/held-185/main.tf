resource "aws_s3_bucket" "c185" {
  bucket = "clean-185-assets"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "c185" {
  bucket = aws_s3_bucket.c185.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "c185" {
  bucket = aws_s3_bucket.c185.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "c185" {
  bucket = aws_s3_bucket.c185.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "c185" {
  bucket = aws_s3_bucket.c185.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "EnforceTLS"
      Effect = "Deny"
      Principal = "*"
      Action = "s3:*"
      Resource = [
        aws_s3_bucket.c185.arn,
        "${aws_s3_bucket.c185.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

resource "aws_s3_bucket_logging" "c185" {
  bucket = aws_s3_bucket.c185.id
  target_bucket = aws_s3_bucket.c185_logs.id
  target_prefix = "log/"
}

resource "aws_s3_bucket" "c185_logs" {
  bucket = "clean-185-assets-logs"
}

resource "aws_s3_bucket_lifecycle_configuration" "c185" {
  bucket = aws_s3_bucket.c185.id
  rule {
    id = "expire-old"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}

