resource "aws_security_group" "vuln" {
  name = "vuln"
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  point_in_time_recovery {
    enabled = true
  }
  deletion_protection_enabled = true
}
