resource "aws_lambda_function" "vuln" {
  function_name = "vuln"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.13"
  handler       = "index.handler"
}
