resource "aws_s3_bucket" "v50" {
  bucket = "vuln-50-data"
}

resource "aws_s3_bucket_acl" "v50" {
  bucket = aws_s3_bucket.v50.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v50" {
  bucket = aws_s3_bucket.v50.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-50-data/*" }]
  })
}

