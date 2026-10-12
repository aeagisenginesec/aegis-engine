resource "aws_sqs_queue" "vuln" {
  name                    = "vuln"
  sqs_managed_sse_enabled = true
}

resource "aws_sqs_queue_policy" "p" {
  queue_url = aws_sqs_queue.vuln.id
  policy    = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "*"
    }
  ]
}
POLICY
}
