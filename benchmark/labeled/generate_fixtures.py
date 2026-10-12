#!/usr/bin/env python3
"""Generate paired vulnerable/secure regression fixtures for the top-20
Critical/High AWS rules under internal/regression/testdata/<rule-id>/.

Each rule gets vulnerable.tf (target rule must fire), secure.tf (zero
findings), and expected.json is written afterwards by scanning (see
write_expected.py) so it records the scanner's actual behavior.
"""
import os

BASE = "/home/hatch/workspace/aegis-engine/internal/regression/testdata"

RDS_QUIET = """  deletion_protection               = true
  backup_retention_period           = 7
  iam_database_authentication_enabled = true
  multi_az                          = true
"""

LB_QUIET = """  drop_invalid_header_fields = true
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
"""

FIXTURES = {
"AEGIS-AWS-001": (
"""resource "aws_s3_bucket" "vuln" {
}
""",
"""resource "aws_s3_bucket" "safe" {
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}
"""),
"AEGIS-AWS-002": (
"""resource "aws_s3_bucket" "vuln" {
  acl = "public-read"
}
""",
"""resource "aws_s3_bucket" "safe" {
  acl = "private"
}
"""),
"AEGIS-AWS-003": (
"""resource "aws_s3_bucket" "vuln" {
}

resource "aws_s3_bucket_policy" "vuln" {
  bucket = aws_s3_bucket.vuln.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::vuln/*"
    }
  ]
}
POLICY
}
""",
"""resource "aws_s3_bucket" "safe" {
}

resource "aws_s3_bucket_policy" "safe" {
  bucket = aws_s3_bucket.safe.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::safe/*"
    },
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::safe", "arn:aws:s3:::safe/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}
POLICY
}
"""),
"AEGIS-AWS-004": (
"""resource "aws_security_group" "vuln" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
"""resource "aws_security_group" "safe" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"""),
"AEGIS-AWS-006": (
"""resource "aws_iam_policy" "vuln" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
}
POLICY
}
""",
"""resource "aws_iam_policy" "safe" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::app-data/*"]}]
}
POLICY
}
"""),
"AEGIS-AWS-007": (
"""resource "aws_db_instance" "vuln" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  publicly_accessible = false
""" + RDS_QUIET + """}
""",
"""resource "aws_db_instance" "safe" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  storage_encrypted   = true
  publicly_accessible = false
""" + RDS_QUIET + """}
"""),
"AEGIS-AWS-011": (
"""resource "aws_db_instance" "vuln" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  storage_encrypted   = true
  publicly_accessible = true
""" + RDS_QUIET + """}
""",
"""resource "aws_db_instance" "safe" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  storage_encrypted   = true
  publicly_accessible = false
""" + RDS_QUIET + """}
"""),
"AEGIS-AWS-101": (
"""resource "aws_iam_role" "vuln" {
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}]
}
POLICY
}
""",
"""resource "aws_iam_role" "safe" {
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
}
POLICY
}
"""),
"AEGIS-AWS-102": (
"""resource "aws_iam_policy" "vuln" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]
}
POLICY
}
""",
"""resource "aws_iam_policy" "safe" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::app-data/*"]}]
}
POLICY
}
"""),
"AEGIS-AWS-103": (
"""resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "vuln" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  storage_encrypted      = true
  publicly_accessible    = true
  vpc_security_group_ids = [aws_security_group.db.id]
""" + RDS_QUIET + """}
""",
"""resource "aws_security_group" "db" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "safe" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  storage_encrypted      = true
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.db.id]
""" + RDS_QUIET + """}
"""),
"AEGIS-AWS-104": (
"""resource "aws_s3_bucket" "vuln" {
  acl = "public-read"
}
""",
"""resource "aws_s3_bucket" "safe" {
  acl = "private"
}
"""),
"AEGIS-AWS-105": (
"""resource "aws_security_group" "a" {
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "b" {
  ingress {
    from_port                = 5432
    to_port                  = 5432
    protocol                 = "tcp"
    source_security_group_id = aws_security_group.a.id
  }
}

resource "aws_db_instance" "vuln" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  storage_encrypted      = true
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.b.id]
""" + RDS_QUIET + """}
""",
"""resource "aws_security_group" "only" {
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "safe" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  storage_encrypted      = true
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.only.id]
""" + RDS_QUIET + """}
"""),
"AEGIS-AWS-201": (
"""resource "aws_lb" "vuln" {
  internal           = false
  load_balancer_type = "application"
""" + LB_QUIET + """}
""",
"""resource "aws_lb" "safe" {
  internal           = true
  load_balancer_type = "application"
""" + LB_QUIET + """}
"""),
"AEGIS-AWS-202": (
"""resource "aws_lb" "vuln" {
  internal           = true
  load_balancer_type = "application"
""" + LB_QUIET + """}

resource "aws_lb_listener" "vuln" {
  load_balancer_arn = aws_lb.vuln.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
    }
  }
}
""",
"""resource "aws_lb" "safe" {
  internal           = true
  load_balancer_type = "application"
""" + LB_QUIET + """}

resource "aws_lb_listener" "safe" {
  load_balancer_arn = aws_lb.safe.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/abc"
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
    }
  }
}
"""),
"AEGIS-AWS-203": (
"""resource "aws_lb" "vuln" {
  internal                   = true
  load_balancer_type         = "application"
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}
""",
"""resource "aws_lb" "safe" {
  internal           = true
  load_balancer_type = "application"
""" + LB_QUIET + """}
"""),
"AEGIS-AWS-204": (
"""resource "aws_instance" "vuln" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
}
""",
"""resource "aws_instance" "safe" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
  metadata_options {
    http_tokens = "required"
  }
}
"""),
"AEGIS-AWS-501": (
"""resource "aws_iam_policy" "vuln" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["iam:CreatePolicy", "iam:AttachRolePolicy"], "Resource": "*"}]
}
POLICY
}
""",
"""resource "aws_iam_policy" "safe" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::app-data/*"]}]
}
POLICY
}
"""),
"AEGIS-AWS-502": (
"""resource "aws_iam_policy" "vuln" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}]
}
POLICY
}
""",
"""resource "aws_iam_policy" "safe" {
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::app-data/*"]}]
}
POLICY
}
"""),
"AEGIS-AWS-534": (
"""resource "aws_instance" "vuln" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
  user_data     = "DB_PASSWORD=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  metadata_options {
    http_tokens = "required"
  }
}
""",
"""resource "aws_instance" "safe" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
  user_data     = "#!/bin/bash\\necho hello"
  metadata_options {
    http_tokens = "required"
  }
}
"""),
"AEGIS-AWS-629": (
"""resource "aws_security_group" "web" {
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-12345678"
  instance_type          = "t3.micro"
  monitoring             = true
  vpc_security_group_ids = [aws_security_group.web.id]
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_db_instance" "data" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  storage_encrypted      = true
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.web.id]
""" + RDS_QUIET + """}
""",
"""resource "aws_security_group" "web" {
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-12345678"
  instance_type          = "t3.micro"
  monitoring             = true
  vpc_security_group_ids = [aws_security_group.web.id]
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_db_instance" "data" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  storage_encrypted      = true
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.web.id]
""" + RDS_QUIET + """}
"""),
}

def main():
    for rid, (vuln, secure) in FIXTURES.items():
        d = os.path.join(BASE, rid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "vulnerable.tf"), "w") as f:
            f.write(vuln)
        with open(os.path.join(d, "secure.tf"), "w") as f:
            f.write(secure)
    print(f"wrote {len(FIXTURES)} fixture pairs")

if __name__ == "__main__":
    main()
