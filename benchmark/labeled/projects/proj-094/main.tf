resource "aws_lambda_function" "vuln" {
  function_name = "vuln"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.13"
  handler       = "index.handler"
  environment {
    variables = {
      LOG_LEVEL = "info"
    }
    kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc"
  }
  tracing_config {
    mode = "Active"
  }
  code_signing_config {
  }
  vpc_config {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
