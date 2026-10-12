resource "aws_s3_bucket" "v22" {
  bucket = "vuln-22-data"
}

resource "aws_s3_bucket_acl" "v22" {
  bucket = aws_s3_bucket.v22.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v22" {
  bucket = aws_s3_bucket.v22.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-22-data/*" }]
  })
}

