#!/usr/bin/env python3
"""Generate the labeled AWS detection-correctness corpus.

Writes benchmark/labeled/projects/proj-000..proj-099 (main.tf each) and
benchmark/labeled/manifest.json. Labels reflect rule trigger logic read
from internal/rules/aws/*.go; run score.py afterwards and reconcile any
project where expected rule_ids do not fire.
"""
import json
import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "projects")

# ---------------------------------------------------------------------------
# reusable snippets that silence incidental rules on fixtures
# ---------------------------------------------------------------------------

S3_SSE = """  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
"""

def s3_companions(b, pab=True, pab_all_true=True):
    if pab_all_true:
        pab_block = f"""\
resource "aws_s3_bucket_public_access_block" "pab" {{
  bucket                  = aws_s3_bucket.{b}.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
"""
    else:
        pab_block = f"""\
resource "aws_s3_bucket_public_access_block" "pab" {{
  bucket                  = aws_s3_bucket.{b}.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
"""
    if not pab:
        pab_block = ""
    return f"""\
resource "aws_s3_bucket_versioning" "v" {{
  bucket = aws_s3_bucket.{b}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}

resource "aws_s3_bucket_logging" "l" {{
  bucket        = aws_s3_bucket.{b}.id
  target_bucket = aws_s3_bucket.{b}.id
  target_prefix = "logs/"
}}

resource "aws_s3_bucket_object_lock_configuration" "ol" {{
  bucket = aws_s3_bucket.{b}.id
  rule {{
    default_retention {{
      mode = "COMPLIANCE"
      days = 30
    }}
  }}
}}

{pab_block}"""

def tls_deny_policy(b):
    return f"""\
resource "aws_s3_bucket_policy" "tls" {{
  bucket = aws_s3_bucket.{b}.id
  policy = <<POLICY
{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::{b}", "arn:aws:s3:::{b}/*"],
      "Condition": {{"Bool": {{"aws:SecureTransport": "false"}}}}
    }}
  ]
}}
POLICY
}}
"""

PUBLIC_READ_POLICY = """\
resource "aws_s3_bucket_policy" "pub" {
  bucket = aws_s3_bucket.vuln.id
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::vuln/*"
    },
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::vuln", "arn:aws:s3:::vuln/*"],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    }
  ]
}
POLICY
}
"""

RDS_HARDENED = """  storage_encrypted                  = true
  deletion_protection                = true
  publicly_accessible                = false
  backup_retention_period            = 7
  iam_database_authentication_enabled = true
  multi_az                           = true
"""

EC2_IMDSV2 = """  metadata_options {
    http_tokens = "required"
  }
"""

PROJECTS = []

def add(pid, vulnerable, body, expected, extra=None):
    PROJECTS.append((pid, vulnerable, body, expected, extra or {}))

def s3_bucket(name, inner):
    return f"""resource "aws_s3_bucket" "{name}" {{
{inner}}}
"""

# ============================ VULNERABLE (proj-000..069) ============================

# --- S3 ---------------------------------------------------------------------
add("proj-000", True,
    s3_bucket("vuln", "") + s3_companions("vuln") + tls_deny_policy("vuln"),
    [("AEGIS-AWS-001", "aws_s3_bucket.vuln", "unencrypted bucket (SSE config absent)")])

add("proj-001", True,
    s3_bucket("vuln", """  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = ""
      }
    }
  }
""") + s3_companions("vuln") + tls_deny_policy("vuln"),
    [("AEGIS-AWS-001", "aws_s3_bucket.vuln", "SSE block present but algorithm empty")])

add("proj-002", True,
    s3_bucket("vuln", '  acl = "public-read"\n' + S3_SSE) + s3_companions("vuln") + tls_deny_policy("vuln"),
    [("AEGIS-AWS-002", "aws_s3_bucket.vuln", "public-read ACL"),
     ("AEGIS-AWS-104", "aws_s3_bucket.vuln", "public exfiltration path via ACL")])

add("proj-003", True,
    s3_bucket("vuln", S3_SSE) + s3_companions("vuln") + PUBLIC_READ_POLICY,
    [("AEGIS-AWS-003", "aws_s3_bucket_policy.pub", "bucket policy Allow Principal *"),
     ("AEGIS-AWS-104", "aws_s3_bucket.vuln", "public exfiltration path via policy")])

add("proj-004", True,
    s3_bucket("vuln", S3_SSE) + s3_companions("vuln", pab_all_true=False) + tls_deny_policy("vuln"),
    [("AEGIS-AWS-206", "aws_s3_bucket.vuln", "public access block not fully enabled")])

# --- RDS encryption (007) ----------------------------------------------------
def rds(attrs):
    return f"""resource "aws_db_instance" "vuln" {{
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "admin"
{attrs}}}
"""

add("proj-005", True,
    rds("  deletion_protection = true\n  publicly_accessible = false\n  backup_retention_period = 7\n  iam_database_authentication_enabled = true\n  multi_az = true\n"),
    [("AEGIS-AWS-007", "aws_db_instance.vuln", "storage_encrypted absent (default false)")])

add("proj-006", True,
    rds("  storage_encrypted = false\n  deletion_protection = true\n  publicly_accessible = false\n"),
    [("AEGIS-AWS-007", "aws_db_instance.vuln", "explicit storage_encrypted = false")])

add("proj-007", True,
    rds("  storage_encrypted = var.encrypt_storage\n  deletion_protection = true\n  publicly_accessible = false\n") + """\
variable "encrypt_storage" {
  type    = bool
  default = false
}
""",
    [("AEGIS-AWS-007", "aws_db_instance.vuln", "storage_encrypted via var with insecure default")])

# --- EFS / EBS / DynamoDB / messaging encryption ------------------------------
add("proj-008", True,
    'resource "aws_efs_file_system" "vuln" {\n}\n',
    [("AEGIS-AWS-317", "aws_efs_file_system.vuln", "encrypted absent (default unencrypted)")])

add("proj-009", True,
    'resource "aws_efs_file_system" "vuln" {\n  encrypted = false\n}\n',
    [("AEGIS-AWS-317", "aws_efs_file_system.vuln", "explicit encrypted = false")])

add("proj-010", True,
    'resource "aws_ebs_volume" "vuln" {\n  availability_zone = "us-east-1a"\n  size              = 40\n  encrypted         = false\n}\n',
    [("AEGIS-AWS-009", "aws_ebs_volume.vuln", "explicit encrypted = false")])

add("proj-011", True,
    'resource "aws_instance" "vuln" {\n  ami           = "ami-12345678"\n  instance_type = "t3.micro"\n  monitoring    = true\n' + EC2_IMDSV2 + """  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 30
    encrypted   = false
  }
}
""",
    [("AEGIS-AWS-411", "aws_instance.vuln", "ebs_block_device encrypted = false")])

add("proj-012", True,
    'resource "aws_dynamodb_table" "vuln" {\n  name         = "vuln"\n  billing_mode = "PAY_PER_REQUEST"\n  hash_key     = "id"\n  attribute {\n    name = "id"\n    type = "S"\n  }\n}\n',
    [("AEGIS-AWS-313", "aws_dynamodb_table.vuln", "no customer-managed encryption")])

add("proj-013", True,
    'resource "aws_sns_topic" "vuln" {\n  name = "vuln"\n}\n',
    [("AEGIS-AWS-341", "aws_sns_topic.vuln", "no kms_master_key_id")])

add("proj-014", True,
    'resource "aws_sqs_queue" "vuln" {\n  name                      = "vuln"\n  sqs_managed_sse_enabled   = false\n}\n',
    [("AEGIS-AWS-342", "aws_sqs_queue.vuln", "SSE explicitly disabled")])

add("proj-015", True,
    'resource "aws_secretsmanager_secret" "vuln" {\n  name = "vuln"\n}\n',
    [("AEGIS-AWS-563", "aws_secretsmanager_secret.vuln", "no customer-managed KMS key")])

add("proj-016", True,
    'resource "aws_kms_key" "vuln" {\n  description = "vuln"\n}\n',
    [("AEGIS-AWS-335", "aws_kms_key.vuln", "enable_key_rotation absent")])

add("proj-017", True,
    'resource "aws_kms_key" "vuln" {\n  description         = "vuln"\n  enable_key_rotation = false\n}\n',
    [("AEGIS-AWS-335", "aws_kms_key.vuln", "explicit enable_key_rotation = false")])

add("proj-018", True,
    'resource "aws_redshift_cluster" "vuln" {\n  cluster_identifier = "vuln"\n  node_type          = "dc2.large"\n  master_username    = "admin"\n  cluster_subnet_group_name = "vuln-subnet-group"\n  logging {\n    bucket_name = "redshift-logs-bucket"\n  }\n}\n',
    [("AEGIS-AWS-314", "aws_redshift_cluster.vuln", "encrypted absent")])

add("proj-019", True,
    'resource "aws_eks_cluster" "vuln" {\n  name     = "vuln"\n  role_arn = "arn:aws:iam::123456789012:role/eks"\n  enabled_cluster_log_types = ["api", "audit", "authenticator"]\n}\n',
    [("AEGIS-AWS-304", "aws_eks_cluster.vuln", "no encryption_config for secrets")])

add("proj-020", True,
    'resource "aws_ssm_parameter" "vuln" {\n  name  = "/prod/db/password"\n  type  = "String"\n  value = "SuperSecret123!"\n}\n',
    [("AEGIS-AWS-338", "aws_ssm_parameter.vuln", "plaintext String parameter, secret-like name")])

add("proj-021", True,
    'resource "aws_secretsmanager_secret" "vuln" {\n  name       = "vuln"\n  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"\n}\nresource "aws_secretsmanager_secret_version" "v" {\n  secret_id     = aws_secretsmanager_secret.vuln.id\n  secret_string = "hardcoded-secret-value-123"\n}\n',
    [("AEGIS-AWS-425", "aws_secretsmanager_secret_version.v", "hardcoded secret_string")])

# --- Security groups (004) -----------------------------------------------------
SG_OPEN_22 = """\
resource "aws_security_group" "vuln" {
  name = "vuln"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""

add("proj-022", True, SG_OPEN_22,
    [("AEGIS-AWS-004", "aws_security_group.vuln", "SSH open to 0.0.0.0/0")])

add("proj-023", True, """\
resource "aws_security_group" "vuln" {
  name = "vuln"
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  point_in_time_recovery {
    enabled = true
  }
  deletion_protection_enabled = true
}
""",
    [("AEGIS-AWS-004", "aws_security_group.vuln", "RDP open to 0.0.0.0/0")])

add("proj-024", True, """\
resource "aws_security_group" "vuln" {
  name = "vuln"
}

resource "aws_security_group_rule" "https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.vuln.id
}
""",
    [("AEGIS-AWS-004", "aws_security_group_rule.https", "standalone ingress rule open to world")])

add("proj-025", True, """\
variable "allowed_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

resource "aws_security_group" "vuln" {
  name = "vuln"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs
  }
}
""",
    [("AEGIS-AWS-004", "aws_security_group.vuln", "world CIDR via variable default")])

# --- Network: subnet / LB / EC2 / launch config --------------------------------
add("proj-026", True, """\
resource "aws_subnet" "vuln" {
  vpc_id                  = "vpc-12345678"
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}
""",
    [("AEGIS-AWS-205", "aws_subnet.vuln", "auto-assign public IPs")])

add("proj-027", True, """\
resource "aws_lb" "vuln" {
  name                       = "vuln"
  internal                   = false
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}
""",
    [("AEGIS-AWS-201", "aws_lb.vuln", "explicit internal = false")])

add("proj-028", True, """\
resource "aws_lb" "vuln" {
  name                       = "vuln"
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}
""",
    [("AEGIS-AWS-201", "aws_lb.vuln", "internal absent (default internet-facing)")])

add("proj-029", True, """\
resource "aws_lb" "vuln" {
  name                       = "vuln"
  internal                   = true
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}

resource "aws_lb_listener" "http" {
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
    [("AEGIS-AWS-202", "aws_lb_listener.http", "plain HTTP listener"),
     ("AEGIS-AWS-510", "aws_lb_listener.http", "no HTTP-to-HTTPS redirect")])

add("proj-030", True, """\
resource "aws_lb" "vuln" {
  name               = "vuln"
  internal           = true
  load_balancer_type = "application"
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}
""",
    [("AEGIS-AWS-203", "aws_lb.vuln", "drop_invalid_header_fields absent")])

add("proj-031", True, """\
resource "aws_lb" "vuln" {
  name                       = "vuln"
  internal                   = true
  load_balancer_type         = "application"
  drop_invalid_header_fields = false
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}
""",
    [("AEGIS-AWS-203", "aws_lb.vuln", "explicit drop_invalid_header_fields = false")])

add("proj-032", True, """\
resource "aws_elb" "vuln" {
  name = "vuln"
  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "HTTP"
  }
  access_logs {
    bucket = "elb-logs-bucket"
  }
}
""",
    [("AEGIS-AWS-401", "aws_elb.vuln", "classic ELB plain-HTTP listener")])

add("proj-033", True, """\
resource "aws_instance" "vuln" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
}
""",
    [("AEGIS-AWS-204", "aws_instance.vuln", "metadata_options absent (IMDSv1 allowed)")])

add("proj-034", True, """\
resource "aws_instance" "vuln" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
  metadata_options {
    http_tokens = "optional"
  }
}
""",
    [("AEGIS-AWS-204", "aws_instance.vuln", "explicit http_tokens = optional")])

add("proj-035", True, """\
resource "aws_launch_configuration" "vuln" {
  name          = "vuln"
  image_id      = "ami-12345678"
  instance_type = "t3.micro"
}
""",
    [("AEGIS-AWS-541", "aws_launch_configuration.vuln", "no IMDSv2 enforcement"),
     ("AEGIS-AWS-309", "aws_launch_configuration.vuln", "deprecated launch configuration")])

add("proj-036", True,
    rds(RDS_HARDENED.replace("publicly_accessible                = false", "publicly_accessible                = true")),
    [("AEGIS-AWS-011", "aws_db_instance.vuln", "publicly_accessible = true")])

add("proj-037", True, """\
resource "aws_redshift_cluster" "vuln" {
  cluster_identifier   = "vuln"
  node_type            = "dc2.large"
  master_username      = "admin"
  encrypted            = true
  publicly_accessible  = true
  cluster_subnet_group_name = "vuln-subnet-group"
  logging {
    bucket_name = "redshift-logs-bucket"
  }
}
""",
    [("AEGIS-AWS-315", "aws_redshift_cluster.vuln", "publicly_accessible = true")])

add("proj-038", True, """\
resource "aws_eks_cluster" "vuln" {
  name     = "vuln"
  role_arn = "arn:aws:iam::123456789012:role/eks"
  enabled_cluster_log_types = ["api", "audit", "authenticator"]
  encryption_config {
    provider {
      key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc"
    }
    resources = ["secrets"]
  }
  vpc_config {
    endpoint_public_access = true
  }
}
""",
    [("AEGIS-AWS-305", "aws_eks_cluster.vuln", "public cluster endpoint")])

add("proj-039", True, """\
resource "aws_lambda_function" "vuln" {
  function_name = "vuln"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.13"
  handler       = "index.handler"
}
""",
    [("AEGIS-AWS-542", "aws_lambda_function.vuln", "no vpc_config")])

# --- correlated network paths ----------------------------------------------------
add("proj-040", True, """\
resource "aws_security_group" "db" {
  name = "db"
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
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = true
  backup_retention_period             = 7
  iam_database_authentication_enabled = true
  multi_az                            = true
  vpc_security_group_ids              = [aws_security_group.db.id]
}
""",
    [("AEGIS-AWS-011", "aws_db_instance.vuln", "publicly_accessible = true"),
     ("AEGIS-AWS-004", "aws_security_group.db", "SG open to world"),
     ("AEGIS-AWS-103", "aws_db_instance.vuln", "internet -> SG -> RDS path")])

add("proj-041", True, """\
resource "aws_security_group" "a" {
  name = "edge"
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "b" {
  name = "mid"
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
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  iam_database_authentication_enabled = true
  multi_az                            = true
  vpc_security_group_ids              = [aws_security_group.b.id]
}
""",
    [("AEGIS-AWS-004", "aws_security_group.a", "edge SG open to world"),
     ("AEGIS-AWS-105", "aws_db_instance.vuln", "multi-hop path internet -> SG-a -> SG-b -> RDS")])

add("proj-042", True, """\
resource "aws_sns_topic" "vuln" {
  name             = "vuln"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "sub" {
  topic_arn = aws_sns_topic.vuln.arn
  protocol  = "http"
  endpoint  = "http://example.com/hook"
}
""",
    [("AEGIS-AWS-426", "aws_sns_topic_subscription.sub", "subscription over plaintext HTTP")])

add("proj-043", True, """\
resource "aws_lb" "vuln" {
  name                       = "vuln"
  internal                   = true
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}

resource "aws_lb_listener" "tls" {
  load_balancer_arn = aws_lb.vuln.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:123456789012:certificate/abc"
  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      status_code  = "200"
    }
  }
}
""",
    [("AEGIS-AWS-324", "aws_lb_listener.tls", "pre-TLS-1.2 security policy")])

# --- IAM --------------------------------------------------------------------------
add("proj-044", True, """\
resource "aws_iam_policy" "vuln" {
  name   = "vuln"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}
""",
    [("AEGIS-AWS-006", "aws_iam_policy.vuln", "Allow Action * on Resource *"),
     ("AEGIS-AWS-102", "aws_iam_policy.vuln", "administrative managed policy"),
     ("AEGIS-AWS-501", "aws_iam_policy.vuln", "policy authoring + attachment via *"),
     ("AEGIS-AWS-502", "aws_iam_policy.vuln", "iam:PassRole + compute primitive via *"),
     ("AEGIS-AWS-503", "aws_iam_policy.vuln", "data exfiltration primitives via *"),
     ("AEGIS-AWS-504", "aws_iam_policy.vuln", "permissions-management actions via *")])

add("proj-045", True, """\
resource "aws_iam_policy" "vuln" {
  name   = "vuln"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:*",
      "Resource": "*"
    }
  ]
}
POLICY
}
""",
    [("AEGIS-AWS-102", "aws_iam_policy.vuln", "iam:* on *"),
     ("AEGIS-AWS-501", "aws_iam_policy.vuln", "policy authoring + attachment via iam:*"),
     ("AEGIS-AWS-504", "aws_iam_policy.vuln", "permissions-management actions via iam:*"),
     ("AEGIS-AWS-505", "aws_iam_policy.vuln", "write actions via iam:*")])

add("proj-046", True, """\
resource "aws_iam_role" "vuln" {
  name = "vuln"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}
""",
    [("AEGIS-AWS-101", "aws_iam_role.vuln", "trust policy Principal *")])

add("proj-047", True, """\
resource "aws_iam_policy" "vuln" {
  name   = "vuln"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:CreatePolicy", "iam:AttachRolePolicy"],
      "Resource": "*"
    }
  ]
}
POLICY
}
""",
    [("AEGIS-AWS-501", "aws_iam_policy.vuln", "policy authoring + attachment primitives"),
     ("AEGIS-AWS-504", "aws_iam_policy.vuln", "IAM perms-mgmt actions on *"),
     ("AEGIS-AWS-505", "aws_iam_policy.vuln", "write actions on *")])

add("proj-048", True, """\
resource "aws_iam_policy" "vuln" {
  name   = "vuln"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:PassRole", "ec2:RunInstances"],
      "Resource": "*"
    }
  ]
}
POLICY
}
""",
    [("AEGIS-AWS-502", "aws_iam_policy.vuln", "iam:PassRole on * with compute launch"),
     ("AEGIS-AWS-505", "aws_iam_policy.vuln", "write actions on *")])

add("proj-049", True, """\
resource "aws_sns_topic" "vuln" {
  name              = "vuln"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "p" {
  arn    = aws_sns_topic.vuln.arn
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sns:Publish",
      "Resource": "*"
    }
  ]
}
POLICY
}
""",
    [("AEGIS-AWS-343", "aws_sns_topic_policy.p", "topic policy Principal *")])

add("proj-050", True, """\
resource "aws_sqs_queue" "vuln" {
  name                    = "vuln"
  sqs_managed_sse_enabled = true
}

resource "aws_sqs_queue_policy" "p" {
  queue_url = aws_sqs_queue.vuln.id
  policy    = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "sqs:SendMessage",
      "Resource": "*"
    }
  ]
}
POLICY
}
""",
    [("AEGIS-AWS-344", "aws_sqs_queue_policy.p", "queue policy Principal *")])

add("proj-051", True, """\
resource "aws_efs_file_system" "vuln" {
  encrypted = true
}

resource "aws_efs_file_system_policy" "p" {
  file_system_id = aws_efs_file_system.vuln.id
  policy         = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "elasticfilesystem:ClientMount",
      "Resource": "*"
    }
  ]
}
POLICY
}
""",
    [("AEGIS-AWS-415", "aws_efs_file_system_policy.p", "EFS policy Principal *")])

add("proj-052", True, """\
resource "aws_elasticache_user" "vuln" {
  user_id       = "vuln"
  user_name     = "vuln"
  engine        = "REDIS"
  access_string = "on ~* &* +@all"
  passwords     = ["TempPassword123!"]
}
""",
    [("AEGIS-AWS-428", "aws_elasticache_user.vuln", "open access string")])

add("proj-053", True, """\
resource "aws_api_gateway_api_key" "vuln" {
  name  = "vuln"
  value = "abcdef1234567890abcdef1234567890"
}
""",
    [("AEGIS-AWS-410", "aws_api_gateway_api_key.vuln", "hardcoded API key value")])

add("proj-054", True, """\
resource "aws_opensearch_domain" "vuln" {
  domain_name = "vuln"
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
  }
  cluster_config {
    instance_count           = 3
    dedicated_master_enabled = true
    zone_awareness_enabled   = true
  }
  vpc_options {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
""",
    [("AEGIS-AWS-637", "aws_opensearch_domain.vuln", "no HTTPS enforcement")])

# --- secrets -----------------------------------------------------------------------
add("proj-055", True,
    rds(RDS_HARDENED + '  password = "HardcodedDBPassword123!"\n'),
    [("AEGIS-AWS-339", "aws_db_instance.vuln", "hardcoded password literal")])

add("proj-056", True,
    rds(RDS_HARDENED + '  password = var.db_password\n') + """\
variable "db_password" {
  type = string
}
""",
    [("AEGIS-AWS-339", "aws_db_instance.vuln", "password = var.db_password, no default (taint)")])

add("proj-057", True,
    rds(RDS_HARDENED + '  password = local.db_password\n') + """\
locals {
  db_password = "LocalHardcodedPassword456!"
}
""",
    [("AEGIS-AWS-339", "aws_db_instance.vuln", "password = local.db_password (literal local)")])

add("proj-058", True, """\
resource "aws_instance" "vuln" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
  user_data     = "DB_PASSWORD=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
""" + EC2_IMDSV2 + """}
""",
    [("AEGIS-AWS-534", "aws_instance.vuln", "secret in user_data")])

add("proj-059", True, """\
resource "aws_lambda_function" "vuln" {
  function_name = "vuln"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.13"
  handler       = "index.handler"
  environment {
    kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc"
    variables = {
      DB_PASSWORD = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  }
  tracing_config {
    mode = "Active"
  }
  code_signing_config {
  }
  vpc_config {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
""",
    [("AEGIS-AWS-649", "aws_lambda_function.vuln", "plaintext secret in env vars")])

add("proj-060", True, """\
variable "db_password" {
  type    = string
  default = "DefaultHardcodedSecret789!"
}
""",
    [("AEGIS-AWS-538", "terraform_variable.db_password", "secret in variable default")])

add("proj-061", True, """\
resource "aws_redshift_cluster" "vuln" {
  cluster_identifier = "vuln"
  node_type          = "dc2.large"
  master_username    = "admin"
  master_password    = "RedshiftMasterPass123!"
  encrypted          = true
  cluster_subnet_group_name = "vuln-subnet-group"
  logging {
    bucket_name = "redshift-logs-bucket"
  }
}
""",
    [("AEGIS-AWS-339", "aws_redshift_cluster.vuln", "hardcoded master_password")])

# --- kill chain + module dimensions --------------------------------------------------
add("proj-062", True, """\
resource "aws_security_group" "web" {
  name = "web"
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
""" + EC2_IMDSV2 + """}

resource "aws_db_instance" "data" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  iam_database_authentication_enabled = true
  multi_az                            = true
  vpc_security_group_ids              = [aws_security_group.web.id]
}
""",
    [("AEGIS-AWS-004", "aws_security_group.web", "world-open SG"),
     ("AEGIS-AWS-629", "aws_db_instance.data", "kill chain internet -> EC2 -> RDS")])

add("proj-063", True, """\
module "s3mod" {
  source = "./modules/s3bucket"
}
""",
    [("AEGIS-AWS-001", "aws_s3_bucket.module.s3mod.data", "unencrypted bucket via module"),
     ("AEGIS-AWS-012", "aws_s3_bucket.module.s3mod.data", "versioning not provable post-expansion"),
     ("AEGIS-AWS-206", "aws_s3_bucket.module.s3mod.data", "PAB not provable post-expansion"),
     ("AEGIS-AWS-443", "aws_s3_bucket.module.s3mod.data", "TLS policy not provable post-expansion"),
     ("AEGIS-AWS-445", "aws_s3_bucket.module.s3mod.data", "logging not provable post-expansion"),
     ("AEGIS-AWS-558", "aws_s3_bucket.module.s3mod.data", "object lock not provable post-expansion")],
    {"modules/s3bucket/main.tf": s3_bucket("data", "")})

add("proj-064", True, """\
module "s3mod" {
  source = "./modules/s3bucket"
}
""",
    [("AEGIS-AWS-002", "aws_s3_bucket.module.s3mod.pub", "public ACL via module"),
     ("AEGIS-AWS-104", "aws_s3_bucket.module.s3mod.pub", "exfiltration path via module"),
     ("AEGIS-AWS-012", "aws_s3_bucket.module.s3mod.pub", "versioning not provable post-expansion"),
     ("AEGIS-AWS-206", "aws_s3_bucket.module.s3mod.pub", "PAB not provable post-expansion"),
     ("AEGIS-AWS-443", "aws_s3_bucket.module.s3mod.pub", "TLS policy not provable post-expansion"),
     ("AEGIS-AWS-445", "aws_s3_bucket.module.s3mod.pub", "logging not provable post-expansion"),
     ("AEGIS-AWS-558", "aws_s3_bucket.module.s3mod.pub", "object lock not provable post-expansion")],
    {"modules/s3bucket/main.tf": s3_bucket("pub", '  acl = "public-read"\n' + S3_SSE)})

add("proj-065", True, """\
module "dbmod" {
  source = "./modules/rds"
}
""",
    [("AEGIS-AWS-007", "aws_db_instance.module.dbmod.data", "unencrypted RDS via module")],
    {"modules/rds/main.tf": rds("  deletion_protection = true\n  publicly_accessible = false\n  backup_retention_period = 7\n  iam_database_authentication_enabled = true\n  multi_az = true\n").replace("aws_db_instance\" \"vuln\"", "aws_db_instance\" \"data\"")})

add("proj-066", True, """\
module "sgmod" {
  source = "./modules/sg"
}
""",
    [("AEGIS-AWS-004", "aws_security_group.module.sgmod.open", "world-open SG via module")],
    {"modules/sg/main.tf": SG_OPEN_22.replace('aws_security_group" "vuln"', 'aws_security_group" "open"')})

add("proj-067", True, """\
module "iammod" {
  source = "./modules/iam"
}
""",
    [("AEGIS-AWS-006", "aws_iam_policy.module.iammod.admin", "admin policy via module"),
     ("AEGIS-AWS-102", "aws_iam_policy.module.iammod.admin", "admin managed policy via module"),
     ("AEGIS-AWS-501", "aws_iam_policy.module.iammod.admin", "priv-esc primitives via *"),
     ("AEGIS-AWS-502", "aws_iam_policy.module.iammod.admin", "PassRole + compute via *"),
     ("AEGIS-AWS-503", "aws_iam_policy.module.iammod.admin", "data exfil via *"),
     ("AEGIS-AWS-504", "aws_iam_policy.module.iammod.admin", "perms-mgmt via *")],
    {"modules/iam/main.tf": """\
resource "aws_iam_policy" "admin" {
  name   = "admin"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
POLICY
}
"""})

add("proj-068", True, """\
variable "bucket_name" {
  type    = string
  default = "app-data-bucket"
}

resource "aws_s3_bucket" "vuln" {
  bucket = var.bucket_name
}
""" + s3_companions("vuln") + tls_deny_policy("vuln"),
    [("AEGIS-AWS-001", "aws_s3_bucket.vuln", "unencrypted bucket, name via variable")])

add("proj-069", True,
    rds(RDS_HARDENED.replace("storage_encrypted                  = true", "storage_encrypted                  = var.encrypt_flag") +
        '  password = "HardcodedDBPassword123!"\n') + """\
variable "encrypt_flag" {
  type = bool
}
""",
    [("AEGIS-AWS-339", "aws_db_instance.vuln",
      "hardcoded password; storage_encrypted unknown (var, no default) must stay silent")])


# ============================ SECURE (proj-070..099) ============================

def secure_s3(name):
    return (s3_bucket(name, S3_SSE) + s3_companions(name) + tls_deny_policy(name))

add("proj-070", False, secure_s3("data"), [])
add("proj-071", False,
    rds(RDS_HARDENED + '  backup_retention_period = 7\n'),
    [])
add("proj-072", False, """\
resource "aws_security_group" "vuln" {
  name = "vuln"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
""", [])
add("proj-073", False, """\
resource "aws_iam_role" "vuln" {
  name = "vuln"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}
""", [])
add("proj-074", False, """\
resource "aws_instance" "vuln" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
""" + EC2_IMDSV2 + """  ebs_block_device {
    device_name = "/dev/sda1"
    volume_size = 30
    encrypted   = true
  }
}
""", [])
add("proj-075", False, """\
resource "aws_kms_key" "vuln" {
  description         = "vuln"
  enable_key_rotation = true
}
""", [])
add("proj-076", False, """\
resource "aws_lambda_function" "vuln" {
  function_name = "vuln"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.13"
  handler       = "index.handler"
  tracing_config {
    mode = "Active"
  }
  code_signing_config {
  }
  vpc_config {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
""", [])
add("proj-077", False, """\
resource "aws_sns_topic" "vuln" {
  name              = "vuln"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "p" {
  arn    = aws_sns_topic.vuln.arn
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": "sns:Publish",
      "Resource": "*"
    }
  ]
}
POLICY
}
""", [])
add("proj-078", False, """\
resource "aws_sqs_queue" "vuln" {
  name                    = "vuln"
  sqs_managed_sse_enabled = true
}
""", [])
add("proj-079", False, """\
resource "aws_efs_file_system" "vuln" {
  encrypted  = true
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"
}
""", [])
add("proj-080", False, """\
resource "aws_dynamodb_table" "vuln" {
  name         = "vuln"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc"
  }
  point_in_time_recovery {
    enabled = true
  }
  deletion_protection_enabled = true
}
""", [])
add("proj-081", False, """\
resource "aws_lb" "vuln" {
  name                       = "vuln"
  internal                   = true
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  access_logs {
    bucket  = "lb-logs-bucket"
    enabled = true
  }
}

resource "aws_lb_listener" "tls" {
  load_balancer_arn = aws_lb.vuln.arn
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
""", [])
add("proj-082", False, """\
resource "aws_eks_cluster" "vuln" {
  name     = "vuln"
  role_arn = "arn:aws:iam::123456789012:role/eks"
  enabled_cluster_log_types = ["api", "audit", "authenticator"]
  encryption_config {
    provider {
      key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc"
    }
    resources = ["secrets"]
  }
  vpc_config {
    endpoint_public_access  = false
    endpoint_private_access = true
  }
}
""", [])
add("proj-083", False, """\
resource "aws_secretsmanager_secret" "vuln" {
  name       = "vuln"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"
}
""", [])
add("proj-084", False, """\
resource "aws_redshift_cluster" "vuln" {
  cluster_identifier  = "vuln"
  node_type           = "dc2.large"
  master_username     = "admin"
  encrypted           = true
  publicly_accessible = false
  cluster_subnet_group_name = "vuln-subnet-group"
  logging {
    bucket_name = "redshift-logs-bucket"
  }
}
""", [])
add("proj-085", False, """\
resource "aws_ssm_parameter" "vuln" {
  name  = "/prod/db/password"
  type  = "SecureString"
  value = "SuperSecret123!"
}
""", [])
add("proj-086", False, """\
resource "aws_elasticache_replication_group" "vuln" {
  replication_group_id = "vuln"
  description          = "vuln"
  transit_encryption_enabled = true
  auth_token                 = "TempAuthToken123456!"
  at_rest_encryption_enabled = true
  snapshot_retention_limit   = 7
}
""", [])
add("proj-087", False, """\
resource "aws_opensearch_domain" "vuln" {
  domain_name = "vuln"
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
  encrypt_at_rest {
    enabled = true
  }
  node_to_node_encryption {
    enabled = true
  }
  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true
  }
  cluster_config {
    instance_count           = 3
    dedicated_master_enabled = true
    zone_awareness_enabled   = true
  }
  vpc_options {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
""", [])
add("proj-088", False, """\
resource "aws_security_group" "db" {
  name = "db"
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_security_group" "app" {
  name = "app"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "vuln" {
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  storage_encrypted                   = true
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  iam_database_authentication_enabled = true
  multi_az                            = true
  vpc_security_group_ids              = [aws_security_group.db.id]
}
""", [])
add("proj-089", False, """\
module "s3mod" {
  source = "./modules/s3bucket"
}
""", [], {"modules/s3bucket/main.tf": secure_s3("data")})
add("proj-090", False, """\
resource "aws_iam_policy" "vuln" {
  name   = "vuln"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::app-data/*"]
    }
  ]
}
POLICY
}
""", [])
add("proj-091", False, """\
variable "encrypt_storage" {
  type    = bool
  default = true
}

resource "aws_db_instance" "vuln" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  storage_encrypted                   = var.encrypt_storage
  deletion_protection                 = true
  publicly_accessible                 = false
  backup_retention_period             = 7
  iam_database_authentication_enabled = true
  multi_az                            = true
}
""", [])
add("proj-092", False, """\
locals {
  imds_setting = "required"
}

resource "aws_instance" "vuln" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  monitoring    = true
  metadata_options {
    http_tokens = local.imds_setting
  }
}
""", [])
add("proj-093", False, """\
resource "aws_sns_topic" "vuln" {
  name              = "vuln"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sqs_queue" "q" {
  name                    = "vuln"
  sqs_managed_sse_enabled = true
}

resource "aws_sns_topic_subscription" "sub" {
  topic_arn = aws_sns_topic.vuln.arn
  protocol  = "https"
  endpoint  = "https://example.com/hook"
}
""", [])
add("proj-094", False, """\
resource "aws_lambda_function" "vuln" {
  function_name = "vuln"
  role          = "arn:aws:iam::123456789012:role/lambda"
  runtime       = "python3.13"
  handler       = "index.handler"
  environment {
    variables = {
      LOG_LEVEL = "info"
    }
    kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/abc"
  }
  tracing_config {
    mode = "Active"
  }
  code_signing_config {
  }
  vpc_config {
    subnet_ids         = ["subnet-12345678"]
    security_group_ids = ["sg-12345678"]
  }
}
""", [])
add("proj-095", False, """\
resource "aws_security_group" "vuln" {
  name = "vuln"
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
""", [])
add("proj-096", False, """\
resource "aws_ebs_volume" "vuln" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = true
  kms_key_id        = "arn:aws:kms:us-east-1:123456789012:key/abc"
}
""", [])
add("proj-097", False, """\
resource "aws_elasticache_replication_group" "vuln" {
  replication_group_id       = "vuln"
  description                = "vuln"
  transit_encryption_enabled = true
  auth_token                 = "TempAuthToken123456!"
  at_rest_encryption_enabled = true
  snapshot_retention_limit   = 7
}
""", [])
add("proj-098", False, """\
resource "aws_efs_file_system" "vuln" {
  encrypted  = true
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"
}

resource "aws_efs_file_system_policy" "p" {
  file_system_id = aws_efs_file_system.vuln.id
  policy         = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
      "Action": ["elasticfilesystem:ClientMount"],
      "Resource": "*",
      "Condition": {"Bool": {"aws:SecureTransport": "true"}}
    }
  ]
}
POLICY
}
""", [])
add("proj-099", False, """\
resource "aws_kms_key" "cmk" {
  description         = "cmk"
  enable_key_rotation = true
}

resource "aws_secretsmanager_secret" "vuln" {
  name       = "vuln"
  kms_key_id = aws_kms_key.cmk.arn
}

resource "aws_dynamodb_table" "vuln" {
  name         = "vuln"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
  attribute {
    name = "id"
    type = "S"
  }
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.cmk.arn
  }
  point_in_time_recovery {
    enabled = true
  }
  deletion_protection_enabled = true
}
""", [])

# ---------------------------------------------------------------------------

def main():
    shutil.rmtree(ROOT, ignore_errors=True)
    manifest = []
    for pid, vulnerable, body, expected, extra in PROJECTS:
        d = os.path.join(ROOT, pid)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "main.tf"), "w") as f:
            f.write(body)
        for rel, content in extra.items():
            p = os.path.join(d, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(content)
        manifest.append({
            "project": pid,
            "vulnerable": vulnerable,
            "expected": [
                {"rule_id": r, "resource": res, "issue": issue}
                for r, res, issue in expected
            ],
        })
    with open(os.path.join(HERE, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    nv = sum(1 for p in PROJECTS if p[1])
    ns = sum(1 for p in PROJECTS if not p[1])
    print(f"wrote {len(PROJECTS)} projects ({nv} vulnerable, {ns} secure)")

if __name__ == "__main__":
    main()
