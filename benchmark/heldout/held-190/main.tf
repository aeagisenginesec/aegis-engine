resource "aws_s3_bucket" "c190" {
  bucket = "clean-190-assets"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "c190" {
  bucket = aws_s3_bucket.c190.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "c190" {
  bucket = aws_s3_bucket.c190.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "c190" {
  bucket = aws_s3_bucket.c190.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "c190" {
  bucket = aws_s3_bucket.c190.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "EnforceTLS"
      Effect = "Deny"
      Principal = "*"
      Action = "s3:*"
      Resource = [
        aws_s3_bucket.c190.arn,
        "${aws_s3_bucket.c190.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

resource "aws_s3_bucket_logging" "c190" {
  bucket = aws_s3_bucket.c190.id
  target_bucket = aws_s3_bucket.c190_logs.id
  target_prefix = "log/"
}

resource "aws_s3_bucket" "c190_logs" {
  bucket = "clean-190-assets-logs"
}

resource "aws_s3_bucket_lifecycle_configuration" "c190" {
  bucket = aws_s3_bucket.c190.id
  rule {
    id = "expire-old"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}

