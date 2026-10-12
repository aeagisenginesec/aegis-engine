resource "aws_cloudtrail" "audit" {
  name                          = "audit"
  s3_bucket_name                = "audit-logs-bucket"
  enable_log_file_validation    = true
  is_multi_region_trail         = true
  include_global_service_events = true
}
