resource "aws_s3_bucket" "c199" {
  bucket = "clean-199-assets"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "c199" {
  bucket = aws_s3_bucket.c199.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "c199" {
  bucket = aws_s3_bucket.c199.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "c199" {
  bucket = aws_s3_bucket.c199.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "c199" {
  bucket = aws_s3_bucket.c199.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid = "EnforceTLS"
      Effect = "Deny"
      Principal = "*"
      Action = "s3:*"
      Resource = [
        aws_s3_bucket.c199.arn,
        "${aws_s3_bucket.c199.arn}/*"
      ]
      Condition = {
        Bool = { "aws:SecureTransport" = "false" }
      }
    }]
  })
}

resource "aws_s3_bucket_logging" "c199" {
  bucket = aws_s3_bucket.c199.id
  target_bucket = aws_s3_bucket.c199_logs.id
  target_prefix = "log/"
}

resource "aws_s3_bucket" "c199_logs" {
  bucket = "clean-199-assets-logs"
}

resource "aws_s3_bucket_lifecycle_configuration" "c199" {
  bucket = aws_s3_bucket.c199.id
  rule {
    id = "expire-old"
    status = "Enabled"
    expiration {
      days = 365
    }
  }
}

