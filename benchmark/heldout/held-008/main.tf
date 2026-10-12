resource "aws_s3_bucket" "v8" {
  bucket = "vuln-8-data"
}

resource "aws_s3_bucket_acl" "v8" {
  bucket = aws_s3_bucket.v8.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v8" {
  bucket = aws_s3_bucket.v8.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-8-data/*" }]
  })
}

