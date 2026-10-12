resource "aws_lambda_function" "vuln" {
  function_name = "vuln"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.13"
  handler       = "index.handler"
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
