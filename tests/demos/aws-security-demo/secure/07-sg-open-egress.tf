resource "aws_security_group" "demo" {
  name        = "demo-open-egress"
  description = "Demo security group with restricted egress (HTTPS to the internal VPC range only)"
  egress {
    description = "HTTPS egress to internal VPC range"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
