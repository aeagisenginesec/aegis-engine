resource "aws_security_group" "db" {
  name = "db-b6f6f9"
  ingress {
    from_port = 5432
    to_port = 5432
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
