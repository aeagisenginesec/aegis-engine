resource "aws_kms_key" "v17" {
  description = "vuln-17"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v17" {
  function_name = "vuln-17"
  role = aws_iam_role.v17.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v17" {
  name = "vuln-17"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

