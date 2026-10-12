


resource "aws_kms_key" "org_ct" {
  description             = "CloudTrail log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}


resource "aws_s3_bucket" "org_ct" {
}

resource "aws_kms_key" "org_ct_key" {
  description             = "SSE key for org_ct"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_s3_bucket_versioning" "org_ct_v" {
  bucket = aws_s3_bucket.org_ct.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "org_ct_sse" {
  bucket = aws_s3_bucket.org_ct.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.org_ct_key.arn
    }
  }
}
resource "aws_s3_bucket_public_access_block" "org_ct_pab" {
  bucket                  = aws_s3_bucket.org_ct.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_logging" "org_ct_log" {
  bucket        = aws_s3_bucket.org_ct.id
  target_bucket = aws_s3_bucket.org_ct_logs.id
  target_prefix = "org_ct/"
}
resource "aws_s3_bucket_lifecycle_configuration" "org_ct_lc" {
  bucket = aws_s3_bucket.org_ct.id
  rule {
    id     = "expire-old"
    status = "Enabled"
    expiration { days = 365 }
  }
}

resource "aws_s3_bucket" "org_ct_logs" {
}
resource "aws_s3_bucket_versioning" "org_ct_logs_v" {
  bucket = aws_s3_bucket.org_ct_logs.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "org_ct_logs_sse" {
  bucket = aws_s3_bucket.org_ct_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "org_ct_logs_pab" {
  bucket                  = aws_s3_bucket.org_ct_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "org_ct_tls" {
  bucket = aws_s3_bucket.org_ct.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.org_ct.arn, "${aws_s3_bucket.org_ct.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.org_ct.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.org_ct.arn
  include_global_service_events = true
}

resource "aws_guardduty_detector" "org" {
  enable = true
}
