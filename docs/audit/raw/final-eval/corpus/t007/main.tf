terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_db_instance" "shop" {
  identifier              = "shop-mysql"
  engine                  = "mysql"
  engine_version          = "8.0.36"
  instance_class          = "db.t3.medium"
  allocated_storage       = 100
  db_name                 = "shopdb"
  username                = "admin"
  password                = "password123"
  publicly_accessible     = true
  storage_encrypted       = false
  backup_retention_period = 0
  deletion_protection     = false
  skip_final_snapshot     = true
  multi_az                = false

  tags = {
    Name = "shop-mysql"
  }
}

resource "aws_security_group" "db_open" {
  name   = "db-open-world"
  vpc_id = "vpc-9f8e7d6c5b4a32109"

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "db-open-world"
  }
}
