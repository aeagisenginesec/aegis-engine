resource "aws_kms_key" "v80" {
  description = "vuln-80"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v80" {
  function_name = "vuln-80"
  role = aws_iam_role.v80.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v80" {
  name = "vuln-80"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

