terraform {
  backend "http" {
    address = "http://state.example.com/terraform"
  }
}

resource "aws_s3_bucket" "v13" {
  bucket = "vuln-13"
}

resource "aws_kms_key" "v13" {
  description = "vuln-13"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v13" {
  function_name = "vuln-13"
  role = aws_iam_role.v13.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v13" {
  name = "vuln-13"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

