

resource "aws_vpc" "strict" {
  cidr_block           = "172.16.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_subnet" "strict_a" {
  vpc_id            = aws_vpc.strict.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}
resource "aws_subnet" "strict_b" {
  vpc_id            = aws_vpc.strict.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}
resource "aws_network_acl" "strict_nacl" {
  vpc_id     = aws_vpc.strict.id
  subnet_ids = [aws_subnet.strict_a.id, aws_subnet.strict_b.id]
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "172.16.0.0/16"
    from_port  = 443
    to_port    = 443
  }
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "172.16.0.0/16"
    from_port  = 443
    to_port    = 443
  }
}
resource "aws_security_group" "strict_sg" {
  name        = "strict-sg"
  description = "strict application security group"
  vpc_id      = aws_vpc.strict.id
  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["172.16.0.0/16"]
  }
  egress {
    description = "HTTPS within VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["172.16.0.0/16"]
  }
}

resource "aws_kms_key" "strict_fl" {
  description             = "VPC flow log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}


resource "aws_iam_role" "strict_fl" {
  name = "strict_fl-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "strict_fl" {
  name              = "/vpc/strict/flowlogs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.strict_fl.arn
}
resource "aws_flow_log" "strict_fl" {
  vpc_id               = aws_vpc.strict.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.strict_fl.arn
  iam_role_arn         = aws_iam_role.strict_fl.arn
}
