variable "bucket_name" {
  type    = string
  default = "app-data-bucket"
}

resource "aws_s3_bucket" "vuln" {
  bucket = var.bucket_name
}
resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.vuln.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "l" {
  bucket        = aws_s3_bucket.vuln.id
  target_bucket = aws_s3_bucket.vuln.id
  target_prefix = "logs/"
}

resource "aws_s3_bucket_object_lock_configuration" "ol" {
  bucket = aws_s3_bucket.vuln.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 30
    }
  }
}

resource "aws_s3_bucket_public_access_block" "pab" {
  bucket                  = aws_s3_bucket.vuln.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.vuln.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::vuln", "arn:aws:s3:::vuln/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}
POLICY
}
