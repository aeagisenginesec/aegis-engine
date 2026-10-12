resource "aws_lambda_function" "webhook" {
  function_name = "webhook"
  role          = "arn:aws:iam::123456789012:role/webhook"
  runtime       = "python3.13"
  handler       = "index.handler"
  tracing_config {
    mode = "Active"
  }
  vpc_config {
    subnet_ids         = ["subnet-0a1b2c3d"]
    security_group_ids = ["sg-0a1b2c3d"]
  }
  reserved_concurrent_executions = 10
  code_signing_config {
  }
  dead_letter_config {
    target_arn = "arn:aws:sqs:us-east-1:123456789012:dlq"
  }
}

resource "aws_lambda_function_url" "webhook" {
  function_name      = aws_lambda_function.webhook.function_name
  authorization_type = "NONE"
}
