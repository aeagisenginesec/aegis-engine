resource "aws_cloudtrail" "demo" {
  name                        = "demo-trail"
  s3_bucket_name              = "demo-trail-bucket"
  enable_log_file_validation  = true
  is_multi_region_trail       = true
}
