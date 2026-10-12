locals {
  service_api_token = "fake-test-secret-003"
  region            = "us-east-1"
}

resource "aws_sns_topic" "alerts" {
  name              = "alerts"
  kms_master_key_id = "alias/aws/sns"
}
