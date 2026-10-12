resource "aws_kms_key" "v33" {
  description = "vuln-33"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v33" {
  function_name = "vuln-33"
  role = aws_iam_role.v33.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v33" {
  name = "vuln-33"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

