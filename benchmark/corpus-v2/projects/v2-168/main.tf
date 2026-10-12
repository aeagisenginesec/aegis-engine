

resource "aws_vpc" "multi" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_subnet" "multi_a" {
  vpc_id            = aws_vpc.multi.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}
resource "aws_subnet" "multi_b" {
  vpc_id            = aws_vpc.multi.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}
resource "aws_network_acl" "multi_nacl" {
  vpc_id     = aws_vpc.multi.id
  subnet_ids = [aws_subnet.multi_a.id, aws_subnet.multi_b.id]
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
resource "aws_security_group" "multi_sg" {
  name        = "multi-sg"
  description = "multi application security group"
  vpc_id      = aws_vpc.multi.id
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

resource "aws_kms_key" "multi_fl" {
  description             = "VPC flow log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}


resource "aws_iam_role" "multi_fl" {
  name = "multi_fl-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "multi_fl" {
  name              = "/vpc/multi/flowlogs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.multi_fl.arn
}
resource "aws_flow_log" "multi_fl" {
  vpc_id               = aws_vpc.multi.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.multi_fl.arn
  iam_role_arn         = aws_iam_role.multi_fl.arn
}

resource "aws_security_group" "admin" {
  name        = "admin-sg"
  description = "admin extra restricted security group"
  vpc_id      = aws_vpc.multi.id
  ingress {
    description = "SSH from admin net"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["172.16.0.0/16"]
  }
  egress {
    description = "DNS within VPC"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["172.16.0.0/16"]
  }
}
