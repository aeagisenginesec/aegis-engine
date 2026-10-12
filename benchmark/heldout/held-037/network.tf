resource "aws_security_group" "v37" {
  name = "vuln-37"
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "v37" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.v37.id]
}

