resource "aws_kms_key" "v27" {
  description = "vuln-27"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v27" {
  function_name = "vuln-27"
  role = aws_iam_role.v27.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v27" {
  name = "vuln-27"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

