resource "aws_iam_user" "reader" {
  name = "reader-58f4f7"
}

resource "aws_iam_user_policy" "reader" {
  user = aws_iam_user.reader.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::reports-58f4f7",
       "arn:aws:s3:::reports-58f4f7/*"]
    }]
  })
}

resource "aws_lambda_function" "hook" {
  function_name = "hook-58f4f7"
  role = "arn:aws:iam::123456789012:role/lambda-exec"
  runtime = "python3.11"
  handler = "index.handler"
  filename = "hook.zip"
}

resource "aws_lambda_function_url" "hook" {
  function_name = aws_lambda_function.hook.function_name
  authorization_type = "NONE"
}
