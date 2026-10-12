resource "aws_cloudtrail" "v87" {
  name = "vuln-87"
  s3_bucket_name = aws_s3_bucket.v87.id
  enable_logging = false
}

resource "aws_s3_bucket" "v87" {
  bucket = "vuln-87-trail"
}

