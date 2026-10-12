

resource "aws_vpc" "hub" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_subnet" "hub_a" {
  vpc_id            = aws_vpc.hub.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}
resource "aws_subnet" "hub_b" {
  vpc_id            = aws_vpc.hub.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}
resource "aws_network_acl" "hub_nacl" {
  vpc_id     = aws_vpc.hub.id
  subnet_ids = [aws_subnet.hub_a.id, aws_subnet.hub_b.id]
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
resource "aws_security_group" "hub_sg" {
  name        = "hub-sg"
  description = "hub application security group"
  vpc_id      = aws_vpc.hub.id
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

resource "aws_kms_key" "hub_fl" {
  description             = "VPC flow log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}


resource "aws_iam_role" "hub_fl" {
  name = "hub_fl-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "hub_fl" {
  name              = "/vpc/hub/flowlogs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.hub_fl.arn
}
resource "aws_flow_log" "hub_fl" {
  vpc_id               = aws_vpc.hub.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.hub_fl.arn
  iam_role_arn         = aws_iam_role.hub_fl.arn
}

resource "aws_guardduty_detector" "hub" {
  enable = true
}
