resource "aws_security_group" "v69" {
  name = "vuln-69"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "v69" {
  bucket = "vuln-69-data"
}

resource "aws_s3_bucket_acl" "v69" {
  bucket = aws_s3_bucket.v69.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v69" {
  bucket = aws_s3_bucket.v69.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-69-data/*" }]
  })
}

