resource "aws_iam_role" "partner" {
  name = "partner-002d2f"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = "*" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_db_instance" "prod" {
  engine = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.medium"
  identifier = "prod-002d2f"
  allocated_storage = 100
  storage_encrypted = true
  publicly_accessible = false
  username = "appadmin"
  password = "Str0ng-002d2f-Db!"
  backup_retention_period = 14
  deletion_protection = true
  multi_az = true
  skip_final_snapshot = false
}

resource "aws_security_group" "app" {
  name = "app-002d2f"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["203.0.113.5/32"]
  }
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
