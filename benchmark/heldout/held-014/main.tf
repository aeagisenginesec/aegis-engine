resource "aws_s3_bucket" "v14" {
  bucket = "vuln-14-data"
}

resource "aws_s3_bucket_acl" "v14" {
  bucket = aws_s3_bucket.v14.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v14" {
  bucket = aws_s3_bucket.v14.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-14-data/*" }]
  })
}

