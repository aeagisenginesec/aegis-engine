resource "aws_kms_key" "v32" {
  description = "vuln-32"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v32" {
  function_name = "vuln-32"
  role = aws_iam_role.v32.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v32" {
  name = "vuln-32"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

terraform {
  backend "http" {
    address = "http://state.example.com/terraform"
  }
}

resource "aws_s3_bucket" "v32" {
  bucket = "vuln-32"
}

