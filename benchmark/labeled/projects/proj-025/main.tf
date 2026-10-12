variable "allowed_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

resource "aws_security_group" "vuln" {
  name = "vuln"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
}
