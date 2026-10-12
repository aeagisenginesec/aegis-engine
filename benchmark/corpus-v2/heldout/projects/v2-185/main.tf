


resource "aws_kms_key" "events_q" {
  description             = "SQS queue encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_sqs_queue" "events" {
  name              = "events-queue"
  kms_master_key_id = aws_kms_key.events_q.arn
}


resource "aws_kms_key" "events_t" {
  description             = "SNS topic encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_sns_topic" "events" {
  name            = "events-topic"
  kms_master_key_id = aws_kms_key.events_t.arn
}
