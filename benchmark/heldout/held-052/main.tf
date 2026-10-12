resource "aws_kms_key" "v52" {
  description = "vuln-52"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v52" {
  function_name = "vuln-52"
  role = aws_iam_role.v52.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v52" {
  name = "vuln-52"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

