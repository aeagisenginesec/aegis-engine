resource "aws_kms_key" "rds" {
  description         = "RDS encryption key"
  enable_key_rotation = true
}

resource "aws_db_subnet_group" "private" {
  name       = "billing-private"
  subnet_ids = ["subnet-c1", "subnet-c2"]
}

resource "aws_db_instance" "billing" {
  identifier              = "billing-pg"
  engine                  = "postgres"
  engine_version          = "15.4"
  instance_class          = var.instance_class
  allocated_storage       = 100
  db_name                 = "billing"
  username                = "billing_admin"
  password                = var.db_password
  db_subnet_group_name    = aws_db_subnet_group.private.name
  publicly_accessible     = false
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.rds.arn
  backup_retention_period = 7
  deletion_protection     = true
  multi_az                = true

  tags = {
    Name = "billing-pg"
  }
}
