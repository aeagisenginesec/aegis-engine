resource "aws_dynamodb_table" "v90" {
  name = "vuln-90"
  hash_key = "id"
  billing_mode = "PAY_PER_REQUEST"
  attribute { name = "id" type = "S" }
}

resource "aws_iam_policy" "v90" {
  name = "vuln-90"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = "dynamodb:*" Resource = "*" }]
  })
}

resource "aws_s3_bucket" "v90" {
  bucket = "vuln-90-data"
}

resource "aws_s3_bucket_acl" "v90" {
  bucket = aws_s3_bucket.v90.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v90" {
  bucket = aws_s3_bucket.v90.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-90-data/*" }]
  })
}

