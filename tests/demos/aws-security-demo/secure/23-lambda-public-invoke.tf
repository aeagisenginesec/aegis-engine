resource "aws_lambda_function" "demo" {
  function_name = "demo-public-invoke"
  role          = "arn:aws:iam::123456789012:role/demo-lambda-role"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "demo.zip"
}
resource "aws_lambda_permission" "demo" {
  statement_id  = "AllowEvents"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.demo.function_name
  principal     = "events.amazonaws.com"
  source_arn    = "arn:aws:events:us-east-1:123456789012:rule/demo-rule"
}
