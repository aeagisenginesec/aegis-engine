resource "aws_lambda_function" "demo" {
  function_name = "demo-no-kms-env"
  role          = "arn:aws:iam::123456789012:role/demo-lambda-role"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "demo.zip"
  environment {
    variables = {
      STAGE = "prod"
    }
  }
}
