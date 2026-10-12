resource "aws_security_group" "v129" {
  name = "vuln-129"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_cloudtrail" "v129" {
  name = "vuln-129"
  s3_bucket_name = aws_s3_bucket.v129.id
  enable_logging = false
}

resource "aws_s3_bucket" "v129" {
  bucket = "vuln-129-trail"
}

