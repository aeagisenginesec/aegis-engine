

resource "aws_sqs_queue" "jobs" {
  name                    = "jobs-queue"
  sqs_managed_sse_enabled = true
}

resource "aws_sns_topic" "jobs" {
  name              = "jobs-topic"
  kms_master_key_id = "alias/aws/sns"
}
