locals {
  webhook_secret = "fake-test-secret-005"
}

resource "aws_lambda_function" "hook" {
  function_name = "hook"
  role          = "arn:aws:iam::123456789012:role/hook"
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
