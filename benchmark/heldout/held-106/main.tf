resource "aws_s3_bucket" "v106" {
  bucket = "vuln-106-data"
}

resource "aws_s3_bucket_acl" "v106" {
  bucket = aws_s3_bucket.v106.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v106" {
  bucket = aws_s3_bucket.v106.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-106-data/*" }]
  })
}

