resource "aws_sns_topic" "demo" {
  name = "demo-topic"
}
resource "aws_sns_topic_policy" "demo" {
  arn    = aws_sns_topic.demo.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.demo.arn
    }]
  })
}
