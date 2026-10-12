resource "aws_kms_key" "v68" {
  description = "vuln-68"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v68" {
  function_name = "vuln-68"
  role = aws_iam_role.v68.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v68" {
  name = "vuln-68"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

