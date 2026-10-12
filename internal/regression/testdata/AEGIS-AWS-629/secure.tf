resource "aws_security_group" "web" {
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-12345678"
  instance_type          = "t3.micro"
  monitoring             = true
  vpc_security_group_ids = [aws_security_group.web.id]
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    encrypted = true
  }
}

resource "aws_db_instance" "data" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  storage_encrypted      = true
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.db.id]
  deletion_protection               = true
  backup_retention_period           = 7
  iam_database_authentication_enabled = true
  multi_az                          = true
}
