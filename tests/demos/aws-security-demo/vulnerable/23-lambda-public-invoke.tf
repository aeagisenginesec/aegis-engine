resource "aws_lambda_function" "demo" {
  function_name = "demo-public-invoke"
  role          = "arn:aws:iam::123456789012:role/demo-lambda-role"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "demo.zip"
}
resource "aws_lambda_permission" "demo" {
  statement_id  = "AllowEveryone"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.demo.function_name
  principal     = "*"
}
