resource "aws_s3_bucket" "v6" {
  bucket = "vuln-6-data"
}

resource "aws_s3_bucket_acl" "v6" {
  bucket = aws_s3_bucket.v6.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v6" {
  bucket = aws_s3_bucket.v6.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-6-data/*" }]
  })
}

resource "aws_ebs_volume" "v6" {
  availability_zone = "us-east-1a"
  size = 40
}

