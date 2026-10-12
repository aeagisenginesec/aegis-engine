resource "aws_security_group" "nat" {
  name        = "nat"
  description = "NAT gateway security group"
  egress {
    description = "all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
