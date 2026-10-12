resource "aws_s3_bucket" "v20" {
  bucket = "vuln-20-data"
}

resource "aws_s3_bucket_acl" "v20" {
  bucket = aws_s3_bucket.v20.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v20" {
  bucket = aws_s3_bucket.v20.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-20-data/*" }]
  })
}

