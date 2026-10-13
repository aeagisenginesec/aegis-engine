terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

resource "aws_kms_key" "rds" {
  description         = "RDS encryption key"
  enable_key_rotation = true
}

resource "aws_db_subnet_group" "private" {
  name       = "analytics-private"
  subnet_ids = ["subnet-aaa111", "subnet-bbb222"]

  tags = {
    Name = "analytics-private"
  }
}

resource "aws_db_parameter_group" "pg15" {
  name   = "analytics-pg15"
  family = "postgres15"

  parameter {
    name  = "log_connections"
    value = "1"
  }
}

resource "aws_db_instance" "analytics" {
  identifier                      = "analytics-pg"
  engine                          = "postgres"
  engine_version                  = "15.4"
  instance_class                  = "db.r6g.large"
  allocated_storage               = 200
  storage_type                    = "gp3"
  db_name                         = "analytics"
  username                        = "dbadmin"
  manage_master_user_password     = true
  db_subnet_group_name            = aws_db_subnet_group.private.name
  parameter_group_name            = aws_db_parameter_group.pg15.name
  publicly_accessible             = false
  storage_encrypted               = true
  kms_key_id                      = aws_kms_key.rds.arn
  backup_retention_period         = 7
  backup_window                   = "02:00-03:00"
  deletion_protection             = true
  multi_az                        = true
  enabled_cloudwatch_logs_exports = ["postgresql"]

  tags = {
    Name = "analytics-pg"
  }
}
