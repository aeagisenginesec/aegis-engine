

resource "aws_s3_bucket" "finance" {
}

resource "aws_kms_key" "finance_key" {
  description             = "SSE key for finance"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_s3_bucket_versioning" "finance_v" {
  bucket = aws_s3_bucket.finance.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "finance_sse" {
  bucket = aws_s3_bucket.finance.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.finance_key.arn
    }
  }
}
resource "aws_s3_bucket_public_access_block" "finance_pab" {
  bucket                  = aws_s3_bucket.finance.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_logging" "finance_log" {
  bucket        = aws_s3_bucket.finance.id
  target_bucket = aws_s3_bucket.finance_logs.id
  target_prefix = "finance/"
}
resource "aws_s3_bucket_lifecycle_configuration" "finance_lc" {
  bucket = aws_s3_bucket.finance.id
  rule {
    id     = "expire-old"
    status = "Enabled"
    expiration { days = 365 }
  }
}

resource "aws_s3_bucket" "finance_logs" {
}
resource "aws_s3_bucket_versioning" "finance_logs_v" {
  bucket = aws_s3_bucket.finance_logs.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "finance_logs_sse" {
  bucket = aws_s3_bucket.finance_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "finance_logs_pab" {
  bucket                  = aws_s3_bucket.finance_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "finance_tls" {
  bucket = aws_s3_bucket.finance.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.finance.arn, "${aws_s3_bucket.finance.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
