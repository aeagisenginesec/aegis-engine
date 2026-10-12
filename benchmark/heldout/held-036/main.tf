resource "aws_cloudtrail" "v36" {
  name = "vuln-36"
  s3_bucket_name = aws_s3_bucket.v36.id
  enable_logging = false
}

resource "aws_s3_bucket" "v36" {
  bucket = "vuln-36-trail"
}

