#!/usr/bin/env python3
"""Phase 5: Held-out corpus generator. Seed 999. Realistic multi-file projects."""
import os, json, random

random.seed(999)
BASE = os.path.expanduser("~/workspace/aegis-engine/benchmark/heldout")
os.makedirs(BASE, exist_ok=True)

# Vulnerability snippets: (id, category, files dict)
# Each vuln is a dict of filename -> content, enabling multi-file realism
VULNS = {
    "kms-lambda": ("kms", {
        "main.tf": '''resource "aws_kms_key" "v{i}" {
  description = "vuln-{i}"
  deletion_window_in_days = 7
}

resource "aws_lambda_function" "v{i}" {
  function_name = "vuln-{i}"
  role = aws_iam_role.v{i}.arn
  handler = "index.handler"
  runtime = "python3.11"
  filename = "code.zip"
}

resource "aws_iam_role" "v{i}" {
  name = "vuln-{i}"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "lambda.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
''',
    }),
    "dynamodb-iam": ("iam", {
        "main.tf": '''resource "aws_dynamodb_table" "v{i}" {
  name = "vuln-{i}"
  hash_key = "id"
  billing_mode = "PAY_PER_REQUEST"
  attribute { name = "id" type = "S" }
}

resource "aws_iam_policy" "v{i}" {
  name = "vuln-{i}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = "dynamodb:*" Resource = "*" }]
  })
}
''',
    }),
    "chain-sg-ec2-rds": ("network", {
        "network.tf": '''resource "aws_security_group" "v{i}" {
  name = "vuln-{i}"
  ingress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "v{i}" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.v{i}.id]
}
''',
        "database.tf": '''resource "aws_db_instance" "v{i}" {
  identifier = "vuln-{i}"
  engine = "mysql"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = "password123"
  skip_final_snapshot = true
}
''',
    }),
    "s3-public-chain": ("exposure", {
        "main.tf": '''resource "aws_s3_bucket" "v{i}" {
  bucket = "vuln-{i}-data"
}

resource "aws_s3_bucket_acl" "v{i}" {
  bucket = aws_s3_bucket.v{i}.id
  acl = "public-read"
}

resource "aws_s3_bucket_policy" "v{i}" {
  bucket = aws_s3_bucket.v{i}.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = "*" Action = "s3:GetObject" Resource = "arn:aws:s3:::vuln-{i}-data/*" }]
  })
}
''',
    }),
    "secret-userdata": ("secrets", {
        "main.tf": '''resource "aws_instance" "v{i}" {
  ami = "ami-12345678"
  instance_type = "t3.micro"
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="SuperSecret123!"
    echo "starting app"
  EOF
}
''',
    }),
    "iam-escalation": ("iam", {
        "main.tf": '''resource "aws_iam_policy" "v{i}" {
  name = "vuln-{i}"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow" Action = "iam:PassRole" Resource = "*" },
      { Effect = "Allow" Action = "ec2:RunInstances" Resource = "*" }
    ]
  })
}
''',
    }),
    "unencrypted-ebs": ("encryption", {
        "main.tf": '''resource "aws_ebs_volume" "v{i}" {
  availability_zone = "us-east-1a"
  size = 40
}
''',
    }),
    "tf-backend-http": ("supply-chain", {
        "main.tf": '''terraform {
  backend "http" {
    address = "http://state.example.com/terraform"
  }
}

resource "aws_s3_bucket" "v{i}" {
  bucket = "vuln-{i}"
}
''',
    }),
    "log-missing": ("logging", {
        "main.tf": '''resource "aws_cloudtrail" "v{i}" {
  name = "vuln-{i}"
  s3_bucket_name = aws_s3_bucket.v{i}.id
  enable_logging = false
}

resource "aws_s3_bucket" "v{i}" {
  bucket = "vuln-{i}-trail"
}
''',
    }),
    "sg-ssh-open": ("network", {
        "main.tf": '''resource "aws_security_group" "v{i}" {
  name = "vuln-{i}"
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
''',
    }),
}

CLEAN_PROJECTS = {
    "clean-web": {
        "main.tf": '''resource "aws_s3_bucket" "c{i}" {
  bucket = "clean-{i}-assets"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "c{i}" {
  bucket = aws_s3_bucket.c{i}.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "c{i}" {
  bucket = aws_s3_bucket.c{i}.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}
''',
        "variables.tf": '''variable "environment" {
  description = "Deployment environment"
  type = string
  default = "production"
}

variable "bucket_prefix" {
  description = "Prefix for bucket names"
  type = string
  default = "clean"
}
''',
        "outputs.tf": '''output "bucket_name" {
  description = "Name of the assets bucket"
  value = aws_s3_bucket.c{i}.id
}
''',
    },
    "clean-db": {
        "main.tf": '''resource "aws_db_instance" "c{i}" {
  identifier = "clean-{i}"
  engine = "postgres"
  instance_class = "db.t3.micro"
  allocated_storage = 20
  username = "admin"
  password = random_password.c{i}.result
  skip_final_snapshot = true
  storage_encrypted = true
  multi_az = true
  backup_retention_period = 7
  publicly_accessible = false
}

resource "random_password" "c{i}" {
  length = 32
  special = true
}
''',
        "variables.tf": '''variable "db_username" {
  description = "Database admin username"
  type = string
  default = "admin"
}
''',
    },
}

manifest = []
vuln_ids = list(VULNS.keys())
clean_ids = list(CLEAN_PROJECTS.keys())

for i in range(200):
    proj = f"held-{i:03d}"
    pdir = os.path.join(BASE, proj)
    os.makedirs(pdir, exist_ok=True)
    os.makedirs(os.path.join(pdir, "modules"), exist_ok=True)

    is_vuln = i < 140  # first 140 vulnerable, last 60 clean (shuffled assignment below)
    expected = []

    if is_vuln:
        # 1-2 vulns per project, weighted toward chain combos
        n = random.choice([1, 1, 1, 2])
        chosen = random.sample(vuln_ids, n)
        for vid in chosen:
            cat, files = VULNS[vid]
            for fname, content in files.items():
                fpath = os.path.join(pdir, fname)
                mode = "a" if os.path.exists(fpath) else "w"
                with open(fpath, mode) as f:
                    f.write(content.replace("{i}", str(i)) + "\n")
            expected.append({"vuln_id": vid, "category": cat})
        # Add realistic variables.tf even for vuln projects
        with open(os.path.join(pdir, "variables.tf"), "w") as f:
            f.write('''variable "project_name" {
  description = "Project identifier"
  type = string
  default = "heldout"
}
''')
    else:
        cid = random.choice(clean_ids)
        for fname, content in CLEAN_PROJECTS[cid].items():
            with open(os.path.join(pdir, fname), "w") as f:
                f.write(content.replace("{i}", str(i)) + "\n")
        expected.append({"vuln_id": "clean", "category": "clean"})

    # Add a dummy module to look realistic
    moddir = os.path.join(pdir, "modules", "networking")
    os.makedirs(moddir, exist_ok=True)
    with open(os.path.join(moddir, "main.tf"), "w") as f:
        f.write('''variable "vpc_cidr" {
  type = string
  default = "10.0.0.0/16"
}

resource "aws_vpc" "mod" {
  cidr_block = var.vpc_cidr
  enable_dns_support = true
}
''')

    manifest.append({"project": proj, "vulnerable": is_vuln, "expected": expected})

# Shuffle manifest order so vuln/clean are mixed (but keep the 140/60 split)
random.shuffle(manifest)

json.dump(manifest, open(os.path.join(os.path.expanduser("~/workspace/aegis-engine/benchmark"), "heldout_manifest.json"), "w"), indent=2)
v = sum(1 for m in manifest if m["vulnerable"])
print(f"Held-out corpus: 200 projects ({v} vuln, {200-v} clean), seed 999")
print(f"Total expected vulns: {sum(len(m['expected']) for m in manifest if m['vulnerable'])}")
