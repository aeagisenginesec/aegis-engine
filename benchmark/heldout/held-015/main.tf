resource "aws_s3_bucket" "v15" {
  bucket = "vuln-15-data"
}

resource "aws_s3_bucket_acl" "v15" {
  bucket = aws_s3_bucket.v15.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v15" {
  bucket = aws_s3_bucket.v15.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-15-data/*" }]
  })
}

