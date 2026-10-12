resource "aws_kms_key" "v73" {
  description = "vuln-73"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v73" {
  function_name = "vuln-73"
  role = aws_iam_role.v73.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v73" {
  name = "vuln-73"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

