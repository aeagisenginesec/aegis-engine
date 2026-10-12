resource "aws_s3_bucket" "v136" {
  bucket = "vuln-136-data"
}

resource "aws_s3_bucket_acl" "v136" {
  bucket = aws_s3_bucket.v136.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v136" {
  bucket = aws_s3_bucket.v136.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-136-data/*" }]
  })
}

