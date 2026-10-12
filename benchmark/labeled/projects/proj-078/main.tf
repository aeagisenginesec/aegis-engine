resource "aws_sqs_queue" "vuln" {
  name                    = "vuln"
  sqs_managed_sse_enabled = true
}
