resource "aws_lambda_function" "hook" {
  function_name = "hook-78613a"
  role = "arn:aws:iam::123456789012:role/lambda-exec"
  runtime = "python3.11"
  handler = "index.handler"
  filename = "hook.zip"
}

resource "aws_lambda_function_url" "hook" {
  function_name = aws_lambda_function.hook.function_name
  authorization_type = "NONE"
}
