resource "aws_cloudtrail" "v23" {
  name = "vuln-23"
  s3_bucket_name = aws_s3_bucket.v23.id
  enable_logging = false
}

resource "aws_s3_bucket" "v23" {
  bucket = "vuln-23-trail"
}

