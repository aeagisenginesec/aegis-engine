resource "aws_sqs_queue" "demo" {
  name                   = "demo-queue"
  sqs_managed_sse_enabled = false
}
