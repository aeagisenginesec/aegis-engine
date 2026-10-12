resource "aws_cloudtrail" "v28" {
  name = "vuln-28"
  s3_bucket_name = aws_s3_bucket.v28.id
  enable_logging = false
}

resource "aws_s3_bucket" "v28" {
  bucket = "vuln-28-trail"
}

resource "aws_dynamodb_table" "v28" {
  name = "vuln-28"
  hash_key = "id"
  billing_mode = "PAY_PER_REQUEST"
  attribute { name = "id" type = "S" }
}

resource "aws_iam_policy" "v28" {
  name = "vuln-28"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = "dynamodb:*" Resource = "*" }]
  })
}

