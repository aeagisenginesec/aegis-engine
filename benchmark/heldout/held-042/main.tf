resource "aws_kms_key" "v42" {
  description = "vuln-42"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v42" {
  function_name = "vuln-42"
  role = aws_iam_role.v42.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v42" {
  name = "vuln-42"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

