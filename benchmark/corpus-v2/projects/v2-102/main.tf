resource "aws_cloudwatch_log_group" "app" {
  name       = "app"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"
}
