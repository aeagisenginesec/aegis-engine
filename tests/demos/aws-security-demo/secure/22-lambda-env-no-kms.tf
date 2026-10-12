resource "aws_lambda_function" "demo" {
  function_name = "demo-no-kms-env"
  role          = "arn:aws:iam::123456789012:role/demo-lambda-role"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "demo.zip"
  kms_key_arn   = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
  environment {
    variables = {
      STAGE = "prod"
    }
  }
}
