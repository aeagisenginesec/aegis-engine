resource "aws_security_group" "v79" {
  name = "vuln-79"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_cloudtrail" "v79" {
  name = "vuln-79"
  s3_bucket_name = aws_s3_bucket.v79.id
  enable_logging = false
}

resource "aws_s3_bucket" "v79" {
  bucket = "vuln-79-trail"
}

