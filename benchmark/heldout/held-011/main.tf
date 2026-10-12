resource "aws_cloudtrail" "v11" {
  name = "vuln-11"
  s3_bucket_name = aws_s3_bucket.v11.id
  enable_logging = false
}

resource "aws_s3_bucket" "v11" {
  bucket = "vuln-11-trail"
}

