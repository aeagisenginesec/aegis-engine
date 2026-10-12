resource "aws_s3_bucket" "v127" {
  bucket = "vuln-127-data"
}

resource "aws_s3_bucket_acl" "v127" {
  bucket = aws_s3_bucket.v127.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v127" {
  bucket = aws_s3_bucket.v127.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-127-data/*" }]
  })
}

