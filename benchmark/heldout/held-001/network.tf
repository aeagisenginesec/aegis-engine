resource "aws_security_group" "v1" {
  name = "vuln-1"
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "v1" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.v1.id]
}

