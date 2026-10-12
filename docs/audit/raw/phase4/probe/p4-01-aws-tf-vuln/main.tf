resource "aws_s3_bucket" "probedata" {
  bucket = "p4-probe-data-001"
  acl    = "public-read"
}

resource "aws_security_group" "probessh" {
  name = "p4-probe-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
