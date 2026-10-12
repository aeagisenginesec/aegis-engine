resource "aws_kms_key" "v94" {
  description = "vuln-94"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v94" {
  function_name = "vuln-94"
  role = aws_iam_role.v94.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v94" {
  name = "vuln-94"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

