resource "aws_cloudtrail" "v96" {
  name = "vuln-96"
  s3_bucket_name = aws_s3_bucket.v96.id
  enable_logging = false
}

resource "aws_s3_bucket" "v96" {
  bucket = "vuln-96-trail"
}

resource "aws_kms_key" "v96" {
  description = "vuln-96"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v96" {
  function_name = "vuln-96"
  role = aws_iam_role.v96.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v96" {
  name = "vuln-96"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}

