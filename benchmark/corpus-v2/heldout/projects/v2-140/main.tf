

resource "aws_s3_bucket" "datalake" {
}

resource "aws_s3_bucket_versioning" "datalake_v" {
  bucket = aws_s3_bucket.datalake.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "datalake_sse" {
  bucket = aws_s3_bucket.datalake.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_public_access_block" "datalake_pab" {
  bucket                  = aws_s3_bucket.datalake.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_logging" "datalake_log" {
  bucket        = aws_s3_bucket.datalake.id
  target_bucket = aws_s3_bucket.datalake_logs.id
  target_prefix = "datalake/"
}
resource "aws_s3_bucket_lifecycle_configuration" "datalake_lc" {
  bucket = aws_s3_bucket.datalake.id
  rule {
    id     = "expire-old"
    status = "Enabled"
    expiration { days = 365 }
  }
}

resource "aws_s3_bucket" "datalake_logs" {
}
resource "aws_s3_bucket_versioning" "datalake_logs_v" {
  bucket = aws_s3_bucket.datalake_logs.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "datalake_logs_sse" {
  bucket = aws_s3_bucket.datalake_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "datalake_logs_pab" {
  bucket                  = aws_s3_bucket.datalake_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "datalake_tls" {
  bucket = aws_s3_bucket.datalake.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.datalake.arn, "${aws_s3_bucket.datalake.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
