

resource "aws_s3_bucket" "backups" {
}

resource "aws_s3_bucket_versioning" "backups_v" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "backups_sse" {
  bucket = aws_s3_bucket.backups.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_public_access_block" "backups_pab" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_logging" "backups_log" {
  bucket        = aws_s3_bucket.backups.id
  target_bucket = aws_s3_bucket.backups_logs.id
  target_prefix = "backups/"
}
resource "aws_s3_bucket_lifecycle_configuration" "backups_lc" {
  bucket = aws_s3_bucket.backups.id
  rule {
    id     = "expire-old"
    status = "Enabled"
    expiration { days = 365 }
  }
}

resource "aws_s3_bucket" "backups_logs" {
}
resource "aws_s3_bucket_versioning" "backups_logs_v" {
  bucket = aws_s3_bucket.backups_logs.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "backups_logs_sse" {
  bucket = aws_s3_bucket.backups_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "backups_logs_pab" {
  bucket                  = aws_s3_bucket.backups_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "backups_tls" {
  bucket = aws_s3_bucket.backups.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.backups.arn, "${aws_s3_bucket.backups.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}


resource "aws_kms_key" "backups_bv" {
  description             = "Backup vault encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_backup_vault" "backups" {
  name        = "backups-vault"
  kms_key_arn = aws_kms_key.backups_bv.arn
}
