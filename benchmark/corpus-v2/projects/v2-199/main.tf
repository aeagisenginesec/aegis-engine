

resource "aws_vpc" "db" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_subnet" "db_a" {
  vpc_id            = aws_vpc.db.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}
resource "aws_subnet" "db_b" {
  vpc_id            = aws_vpc.db.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}
resource "aws_network_acl" "db_nacl" {
  vpc_id     = aws_vpc.db.id
  subnet_ids = [aws_subnet.db_a.id, aws_subnet.db_b.id]
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 443
    to_port    = 443
  }
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "10.0.0.0/16"
    from_port  = 443
    to_port    = 443
  }
}
resource "aws_security_group" "db_sg" {
  name        = "db-sg"
  description = "db application security group"
  vpc_id      = aws_vpc.db.id
  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
  egress {
    description = "HTTPS within VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_kms_key" "db_fl" {
  description             = "VPC flow log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}


resource "aws_iam_role" "db_fl" {
  name = "db_fl-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "db_fl" {
  name              = "/vpc/db/flowlogs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.db_fl.arn
}
resource "aws_flow_log" "db_fl" {
  vpc_id               = aws_vpc.db.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.db_fl.arn
  iam_role_arn         = aws_iam_role.db_fl.arn
}

resource "aws_db_instance" "db" {
  identifier                          = "db-db"
  engine                              = "postgres"
  engine_version                      = "15.4"
  instance_class                      = "db.t3.micro"
  allocated_storage                   = 20
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  multi_az                            = true
  iam_database_authentication_enabled = true
  manage_master_user_password         = true
  enabled_cloudwatch_logs_exports     = ["postgresql"]
}

resource "aws_db_subnet_group" "db" {
  name       = "db-db-subnets"
  subnet_ids = ["subnet-aaa", "subnet-bbb"]
}
