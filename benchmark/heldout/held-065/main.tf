resource "aws_s3_bucket" "v65" {
  bucket = "vuln-65-data"
}

resource "aws_s3_bucket_acl" "v65" {
  bucket = aws_s3_bucket.v65.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v65" {
  bucket = aws_s3_bucket.v65.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-65-data/*" }]
  })
}

