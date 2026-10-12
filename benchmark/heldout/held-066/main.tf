resource "aws_cloudtrail" "v66" {
  name = "vuln-66"
  s3_bucket_name = aws_s3_bucket.v66.id
  enable_logging = false
}

resource "aws_s3_bucket" "v66" {
  bucket = "vuln-66-trail"
}

