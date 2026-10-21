resource "aws_security_group" "app" {
  name   = "secure-app-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "App from office"
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = [var.office_cidr]
  }

  egress {
    description = "Outbound HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "secure-app-sg"
  }
}

resource "aws_instance" "app" {
  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.private_a.id
  vpc_security_group_ids = [aws_security_group.app.id]
  monitoring             = true

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name = "secure-app-01"
  }
}
