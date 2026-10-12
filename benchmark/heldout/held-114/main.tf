resource "aws_s3_bucket" "v114" {
  bucket = "vuln-114-data"
}

resource "aws_s3_bucket_acl" "v114" {
  bucket = aws_s3_bucket.v114.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v114" {
  bucket = aws_s3_bucket.v114.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-114-data/*" }]
  })
}

