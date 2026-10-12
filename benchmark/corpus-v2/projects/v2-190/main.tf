

resource "aws_vpc" "web" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_subnet" "web_a" {
  vpc_id            = aws_vpc.web.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}
resource "aws_subnet" "web_b" {
  vpc_id            = aws_vpc.web.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}
resource "aws_network_acl" "web_nacl" {
  vpc_id     = aws_vpc.web.id
  subnet_ids = [aws_subnet.web_a.id, aws_subnet.web_b.id]
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
resource "aws_security_group" "web_sg" {
  name        = "web-sg"
  description = "web application security group"
  vpc_id      = aws_vpc.web.id
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

resource "aws_kms_key" "web_fl" {
  description             = "VPC flow log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}


resource "aws_iam_role" "web_fl" {
  name = "web_fl-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "web_fl" {
  name              = "/vpc/web/flowlogs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.web_fl.arn
}
resource "aws_flow_log" "web_fl" {
  vpc_id               = aws_vpc.web.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.web_fl.arn
  iam_role_arn         = aws_iam_role.web_fl.arn
}

resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  monitoring    = true
  metadata_options {
    http_tokens = "required"
  }
  root_block_device {
    encrypted = true
  }
  ebs_optimized = true
}

resource "aws_db_instance" "webdb" {
  identifier                          = "webdb-db"
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

resource "aws_lb" "web" {
  name                       = "web-alb"
  internal                   = true
  load_balancer_type         = "application"
  subnets                    = ["subnet-aaa", "subnet-bbb"]
  enable_deletion_protection = true
  drop_invalid_header_fields = true
  access_logs {
    bucket  = "web-alb-logs"
    enabled = true
  }
}
