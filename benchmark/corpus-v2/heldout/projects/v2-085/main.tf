resource "aws_cloudtrail" "audit" {
  name                          = "audit"
  s3_bucket_name                = "audit-logs-bucket"
  kms_key_id                    = "arn:aws:kms:us-east-1:123456789012:key/abc"
  is_multi_region_trail         = true
  include_global_service_events = true
}
