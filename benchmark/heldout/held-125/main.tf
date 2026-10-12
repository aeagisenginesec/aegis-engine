resource "aws_cloudtrail" "v125" {
  name = "vuln-125"
  s3_bucket_name = aws_s3_bucket.v125.id
  enable_logging = false
}

resource "aws_s3_bucket" "v125" {
  bucket = "vuln-125-trail"
}

resource "aws_dynamodb_table" "v125" {
  name = "vuln-125"
  hash_key = "id"
  billing_mode = "PAY_PER_REQUEST"
  attribute { name = "id" type = "S" }
}

resource "aws_iam_policy" "v125" {
  name = "vuln-125"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = "dynamodb:*" Resource = "*" }]
  })
}

