resource "aws_security_group" "v60" {
  name = "vuln-60"
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "v60" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.v60.id]
}

