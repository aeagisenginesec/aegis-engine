resource "aws_sns_topic" "demo" {
  name              = "demo-topic"
  kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
}
