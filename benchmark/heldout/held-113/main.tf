resource "aws_s3_bucket" "v113" {
  bucket = "vuln-113-data"
}

resource "aws_s3_bucket_acl" "v113" {
  bucket = aws_s3_bucket.v113.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v113" {
  bucket = aws_s3_bucket.v113.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-113-data/*" }]
  })
}

