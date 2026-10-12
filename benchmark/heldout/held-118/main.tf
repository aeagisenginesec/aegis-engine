resource "aws_security_group" "v118" {
  name = "vuln-118"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_cloudtrail" "v118" {
  name = "vuln-118"
  s3_bucket_name = aws_s3_bucket.v118.id
  enable_logging = false
}

resource "aws_s3_bucket" "v118" {
  bucket = "vuln-118-trail"
}

