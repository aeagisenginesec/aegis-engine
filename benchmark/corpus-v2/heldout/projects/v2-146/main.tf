

resource "aws_s3_bucket" "snaps" {
}

resource "aws_s3_bucket_versioning" "snaps_v" {
  bucket = aws_s3_bucket.snaps.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "snaps_sse" {
  bucket = aws_s3_bucket.snaps.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
resource "aws_s3_bucket_public_access_block" "snaps_pab" {
  bucket                  = aws_s3_bucket.snaps.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_logging" "snaps_log" {
  bucket        = aws_s3_bucket.snaps.id
  target_bucket = aws_s3_bucket.snaps_logs.id
  target_prefix = "snaps/"
}
resource "aws_s3_bucket_lifecycle_configuration" "snaps_lc" {
  bucket = aws_s3_bucket.snaps.id
  rule {
    id     = "expire-old"
    status = "Enabled"
    expiration { days = 365 }
  }
}

resource "aws_s3_bucket" "snaps_logs" {
}
resource "aws_s3_bucket_versioning" "snaps_logs_v" {
  bucket = aws_s3_bucket.snaps_logs.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "snaps_logs_sse" {
  bucket = aws_s3_bucket.snaps_logs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}
resource "aws_s3_bucket_public_access_block" "snaps_logs_pab" {
  bucket                  = aws_s3_bucket.snaps_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "snaps_tls" {
  bucket = aws_s3_bucket.snaps.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.snaps.arn, "${aws_s3_bucket.snaps.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

resource "aws_ebs_volume" "snap1" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
  type              = "gp3"
}

resource "aws_ebs_volume" "snap2" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
  type              = "gp3"
}
