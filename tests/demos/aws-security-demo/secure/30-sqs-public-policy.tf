resource "aws_sqs_queue" "demo" {
  name = "demo-queue"
}
resource "aws_sqs_queue_policy" "demo" {
  queue_url = aws_sqs_queue.demo.id
  policy    = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "events.amazonaws.com" }
      Action    = "sqs:SendMessage"
      Resource  = aws_sqs_queue.demo.arn
    }]
  })
}
