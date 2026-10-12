resource "aws_sns_topic" "vuln" {
  name              = "vuln"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sqs_queue" "q" {
  name                    = "vuln"
  sqs_managed_sse_enabled = true
}

resource "aws_sns_topic_subscription" "sub" {
  topic_arn = aws_sns_topic.vuln.arn
  protocol  = "https"
  endpoint  = "https://example.com/hook"
}
