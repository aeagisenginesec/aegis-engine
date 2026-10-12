resource "aws_s3_bucket" "v112" {
  bucket = "vuln-112-data"
}

resource "aws_s3_bucket_acl" "v112" {
  bucket = aws_s3_bucket.v112.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v112" {
  bucket = aws_s3_bucket.v112.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-112-data/*" }]
  })
}

resource "aws_dynamodb_table" "v112" {
  name = "vuln-112"
  hash_key = "id"
  billing_mode = "PAY_PER_REQUEST"
  attribute { name = "id" type = "S" }
}

resource "aws_iam_policy" "v112" {
  name = "vuln-112"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = "dynamodb:*" Resource = "*" }]
  })
}

