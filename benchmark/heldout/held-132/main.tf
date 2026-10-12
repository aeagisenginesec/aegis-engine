terraform {
  backend "http" {
    address = "http://state.example.com/terraform"
  }
}

resource "aws_s3_bucket" "v132" {
  bucket = "vuln-132"
}

resource "aws_s3_bucket" "v132" {
  bucket = "vuln-132-data"
}

resource "aws_s3_bucket_acl" "v132" {
  bucket = aws_s3_bucket.v132.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v132" {
  bucket = aws_s3_bucket.v132.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-132-data/*" }]
  })
}

