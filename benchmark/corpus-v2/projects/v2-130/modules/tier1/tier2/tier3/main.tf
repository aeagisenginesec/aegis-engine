
resource "aws_security_group" "deep" {
  name        = "deep-sg"
  description = "buried three modules deep"
  ingress {
    description = "world open"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
