resource "aws_cloudtrail" "demo" {
  name           = "demo-trail"
  s3_bucket_name = "demo-trail-bucket"
}
