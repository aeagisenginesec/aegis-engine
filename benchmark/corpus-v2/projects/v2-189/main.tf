

resource "aws_s3_bucket" "siem" {
}

resource "aws_kms_key" "siem_key" {
  description             = "SSE key for siem"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_s3_bucket_versioning" "siem_v" {
  bucket = aws_s3_bucket.siem.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "siem_sse" {
  bucket = aws_s3_bucket.siem.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.siem_key.arn
    }
  }
}
resource "aws_s3_bucket_public_access_block" "siem_pab" {
  bucket                  = aws_s3_bucket.siem.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_logging" "siem_log" {
  bucket        = aws_s3_bucket.siem.id
  target_bucket = aws_s3_bucket.siem_logs.id
  target_prefix = "siem/"
}
resource "aws_s3_bucket_lifecycle_configuration" "siem_lc" {
  bucket = aws_s3_bucket.siem.id
  rule {
    id     = "expire-old"
    status = "Enabled"
    expiration { days = 365 }
  }
}

resource "aws_s3_bucket" "siem_logs" {
}
resource "aws_s3_bucket_versioning" "siem_logs_v" {
  bucket = aws_s3_bucket.siem_logs.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "siem_logs_sse" {
  bucket = aws_s3_bucket.siem_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "siem_logs_pab" {
  bucket                  = aws_s3_bucket.siem_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "siem_tls" {
  bucket = aws_s3_bucket.siem.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.siem.arn, "${aws_s3_bucket.siem.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_guardduty_detector" "siem" {
  enable = true
}
