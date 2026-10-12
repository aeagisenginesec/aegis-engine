resource "aws_s3_bucket" "v137" {
  bucket = "vuln-137-data"
}

resource "aws_s3_bucket_acl" "v137" {
  bucket = aws_s3_bucket.v137.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v137" {
  bucket = aws_s3_bucket.v137.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-137-data/*" }]
  })
}

