

resource "aws_guardduty_detector" "threat" {
  enable = true
}

resource "aws_sns_topic" "alerts" {
  name              = "alerts-topic"
  kms_master_key_id = "alias/aws/sns"
}
