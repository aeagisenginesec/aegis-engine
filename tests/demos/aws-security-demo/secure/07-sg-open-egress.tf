resource "aws_security_group" "demo" {
  name = "demo-open-egress"
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
