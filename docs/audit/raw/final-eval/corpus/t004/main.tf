terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-central-1"
}

resource "aws_security_group" "app" {
  name        = "app-server-sg"
  description = "Restricted application server access"
  vpc_id      = "vpc-1a2b3c4d5e6f70819"

  ingress {
    description = "HTTPS from office"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }

  ingress {
    description = "SSH from office"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }

  egress {
    description = "Outbound HTTPS for updates"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "app-server-sg"
  }
}

resource "aws_instance" "app" {
  ami                    = "ami-06c39eddbb7f0d3b1"
  instance_type          = "t3.medium"
  monitoring             = true
  ebs_optimized          = true
  vpc_security_group_ids = [aws_security_group.app.id]

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name = "app-server-01"
  }
}
