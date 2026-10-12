resource "aws_sqs_queue" "demo" {
  name            = "demo-queue"
  kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
}
