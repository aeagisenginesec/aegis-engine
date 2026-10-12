resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "vuln" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  storage_encrypted      = true
  publicly_accessible    = true
  vpc_security_group_ids = [aws_security_group.db.id]
  deletion_protection               = true
  backup_retention_period           = 7
  iam_database_authentication_enabled = true
  multi_az                          = true
}
