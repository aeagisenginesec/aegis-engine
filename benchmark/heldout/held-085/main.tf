resource "aws_s3_bucket" "v85" {
  bucket = "vuln-85-data"
}

resource "aws_s3_bucket_acl" "v85" {
  bucket = aws_s3_bucket.v85.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v85" {
  bucket = aws_s3_bucket.v85.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-85-data/*" }]
  })
}

