resource "aws_cloudtrail" "v46" {
  name = "vuln-46"
  s3_bucket_name = aws_s3_bucket.v46.id
  enable_logging = false
}

resource "aws_s3_bucket" "v46" {
  bucket = "vuln-46-trail"
}

resource "aws_kms_key" "v46" {
  description = "vuln-46"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v46" {
  function_name = "vuln-46"
  role = aws_iam_role.v46.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v46" {
  name = "vuln-46"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

