resource "aws_iam_role" "partner" {
  name = "partner-d052e0"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = "*" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_lambda_function" "hook" {
  function_name = "hook-d052e0"
  role = "arn:aws:iam::123456789012:role/lambda-exec"
  runtime = "python3.11"
  handler = "index.handler"
  filename = "hook.zip"
}

resource "aws_lambda_function_url" "hook" {
  function_name = aws_lambda_function.hook.function_name
  authorization_type = "NONE"
}
