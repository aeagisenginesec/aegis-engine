resource "aws_cloudtrail" "v39" {
  name = "vuln-39"
  s3_bucket_name = aws_s3_bucket.v39.id
  enable_logging = false
}

resource "aws_s3_bucket" "v39" {
  bucket = "vuln-39-trail"
}

resource "aws_kms_key" "v39" {
  description = "vuln-39"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v39" {
  function_name = "vuln-39"
  role = aws_iam_role.v39.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v39" {
  name = "vuln-39"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

