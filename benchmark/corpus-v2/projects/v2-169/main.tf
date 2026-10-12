


resource "aws_vpc" "vpcjob" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_subnet" "vpcjob_a" {
  vpc_id            = aws_vpc.vpcjob.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}
resource "aws_subnet" "vpcjob_b" {
  vpc_id            = aws_vpc.vpcjob.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}
resource "aws_network_acl" "vpcjob_nacl" {
  vpc_id     = aws_vpc.vpcjob.id
  subnet_ids = [aws_subnet.vpcjob_a.id, aws_subnet.vpcjob_b.id]
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
resource "aws_security_group" "vpcjob_sg" {
  name        = "vpcjob-sg"
  description = "vpcjob application security group"
  vpc_id      = aws_vpc.vpcjob.id
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

resource "aws_kms_key" "vpcjob_fl" {
  description             = "VPC flow log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}


resource "aws_iam_role" "vpcjob_fl" {
  name = "vpcjob_fl-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "vpcjob_fl" {
  name              = "/vpc/vpcjob/flowlogs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.vpcjob_fl.arn
}
resource "aws_flow_log" "vpcjob_fl" {
  vpc_id               = aws_vpc.vpcjob.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.vpcjob_fl.arn
  iam_role_arn         = aws_iam_role.vpcjob_fl.arn
}

resource "aws_security_group" "vpcjob_sg" {
  name        = "vpcjob-lambda-sg"
  description = "vpcjob lambda security group"
  vpc_id      = aws_vpc.vpcjob.id
  egress {
    description = "HTTPS within VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
resource "aws_lambda_function" "vpcjob" {
  function_name = "vpcjob-fn"
  role          = aws_iam_role.vpcjob_role.arn
  runtime       = "python3.12"
  handler       = "index.handler"
  filename      = "vpcjob.zip"
  tracing_config {
    mode = "Active"
  }
  vpc_config {
    subnet_ids         = [aws_subnet.vpcjob_a.id, aws_subnet.vpcjob_b.id]
    security_group_ids = [aws_security_group.vpcjob_sg.id]
  }
}
