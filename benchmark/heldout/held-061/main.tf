resource "aws_s3_bucket" "v61" {
  bucket = "vuln-61-data"
}

resource "aws_s3_bucket_acl" "v61" {
  bucket = aws_s3_bucket.v61.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v61" {
  bucket = aws_s3_bucket.v61.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-61-data/*" }]
  })
}

