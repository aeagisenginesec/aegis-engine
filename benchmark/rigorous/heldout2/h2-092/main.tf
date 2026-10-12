resource "aws_security_group" "d92" {
  name = "heldout-92"
  ingress {
    from_port = 3389
    to_port = 3389
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
