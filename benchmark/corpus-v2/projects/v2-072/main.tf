resource "aws_lambda_function" "worker" {
  function_name = "worker"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.13"
  handler       = "index.handler"
  environment {
    variables = {
      LOG_LEVEL = "info"
    }
  }
  tracing_config {
    mode = "Active"
  }
  vpc_config {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
  reserved_concurrent_executions = 10
  code_signing_config {
  }
  dead_letter_config {
    target_arn = "arn:aws:sqs:us-east-1:123456789012:worker-dlq"
  }
}
