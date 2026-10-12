

resource "aws_vpc" "cache" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_subnet" "cache_a" {
  vpc_id            = aws_vpc.cache.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
}
resource "aws_subnet" "cache_b" {
  vpc_id            = aws_vpc.cache.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
}
resource "aws_network_acl" "cache_nacl" {
  vpc_id     = aws_vpc.cache.id
  subnet_ids = [aws_subnet.cache_a.id, aws_subnet.cache_b.id]
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
resource "aws_security_group" "cache_sg" {
  name        = "cache-sg"
  description = "cache application security group"
  vpc_id      = aws_vpc.cache.id
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

resource "aws_kms_key" "cache_fl" {
  description             = "VPC flow log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}


resource "aws_iam_role" "cache_fl" {
  name = "cache_fl-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_cloudwatch_log_group" "cache_fl" {
  name              = "/vpc/cache/flowlogs"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.cache_fl.arn
}
resource "aws_flow_log" "cache_fl" {
  vpc_id               = aws_vpc.cache.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.cache_fl.arn
  iam_role_arn         = aws_iam_role.cache_fl.arn
}

resource "aws_elasticache_replication_group" "app" {
  replication_group_id       = "app-redis"
  description                = "app redis"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 1
  engine                     = "redis"
  engine_version             = "7.0"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = "PLACEHOLDER-ChangeMe-9xQ2vL7nR4t"
  snapshot_retention_limit   = 7
}


resource "aws_kms_key" "app_sm" {
  description             = "Secrets Manager encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_secretsmanager_secret" "app" {
  name       = "app-secret"
  kms_key_id = aws_kms_key.app_sm.arn
}
