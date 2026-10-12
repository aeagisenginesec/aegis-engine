resource "aws_sns_topic" "vuln" {
  name             = "vuln"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "sub" {
  topic_arn = aws_sns_topic.vuln.arn
  protocol  = "http"
  endpoint  = "http://example.com/hook"
}
