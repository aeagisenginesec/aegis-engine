#!/usr/bin/env python3
"""Phase 6 LARGE-corpus generator for the Aegis performance/scalability audit.

Generates N Terraform files (default 2000) of realistic, varied AWS content.
Deterministic: fixed seed -> byte-identical corpus on every run.

Each file holds 1-3 resources drawn from 10 templates (s3, sg, rds, iam,
kms, cloudtrail, ec2, secretsmanager, sns, ebs). Each template has a
'secure' and a 'vulnerable' variant; the variant mix is seeded-random
(~60% vulnerable) so the corpus has a realistic, stable finding density.

Resource names are unique per file (suffix = file index) so there is no
cross-file name collision and no dedup ambiguity.

Usage:
    python3 gen_large.py --out /tmp/p6/large --count 2000 [--seed 20261012]
"""
import argparse
import hashlib
import os
import random

SEED = 20261012

TEMPLATES = {
    "s3": {
        "vuln": '''resource "aws_s3_bucket" "p6s3_{i}" {{
  bucket = "p6-bucket-{i:04d}"
  acl    = "public-read"
}}

resource "aws_s3_bucket_versioning" "p6s3v_{i}" {{
  bucket = aws_s3_bucket.p6s3_{i}.id
  versioning_configuration {{
    status = "Suspended"
  }}
}}
''',
        "secure": '''resource "aws_s3_bucket" "p6s3_{i}" {{
  bucket = "p6-bucket-{i:04d}"
}}

resource "aws_s3_bucket_versioning" "p6s3v_{i}" {{
  bucket = aws_s3_bucket.p6s3_{i}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}

resource "aws_s3_bucket_server_side_encryption_configuration" "p6s3e_{i}" {{
  bucket = aws_s3_bucket.p6s3_{i}.id
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}

resource "aws_s3_bucket_public_access_block" "p6s3p_{i}" {{
  bucket                  = aws_s3_bucket.p6s3_{i}.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
''',
    },
    "sg": {
        "vuln": '''resource "aws_security_group" "p6sg_{i}" {{
  name        = "p6-sg-{i:04d}"
  description = "phase6 generated security group"

  ingress {{
    description = "ssh open to world"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}

  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}
''',
        "secure": '''resource "aws_security_group" "p6sg_{i}" {{
  name        = "p6-sg-{i:04d}"
  description = "phase6 generated security group"

  ingress {{
    description = "ssh from office only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }}

  egress {{
    description = "https out only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}
''',
    },
    "rds": {
        "vuln": '''resource "aws_db_instance" "p6rds_{i}" {{
  identifier             = "p6-db-{i:04d}"
  engine                 = "postgres"
  engine_version         = "15.4"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  username               = "admin"
  password               = "p6-change-me-{i:04d}"
  publicly_accessible    = true
  skip_final_snapshot    = true
  backup_retention_period = 0
}}
''',
        "secure": '''resource "aws_db_instance" "p6rds_{i}" {{
  identifier              = "p6-db-{i:04d}"
  engine                  = "postgres"
  engine_version          = "15.4"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "p6-change-me-{i:04d}"
  storage_encrypted       = true
  publicly_accessible     = false
  deletion_protection     = true
  backup_retention_period = 7
  copy_tags_to_snapshot   = true
}}
''',
    },
    "iam": {
        "vuln": '''resource "aws_iam_role" "p6iam_{i}" {{
  name = "p6-role-{i:04d}"
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ AWS = "*" }}
      Action    = "sts:AssumeRole"
    }}]
  }})
}}

resource "aws_iam_role_policy" "p6iamp_{i}" {{
  name = "p6-pol-{i:04d}"
  role = aws_iam_role.p6iam_{i}.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }}]
  }})
}}
''',
        "secure": '''resource "aws_iam_role" "p6iam_{i}" {{
  name = "p6-role-{i:04d}"
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ AWS = "arn:aws:iam::123456789012:root" }}
      Action    = "sts:AssumeRole"
      Condition = {{ Bool = {{ "aws:SecureTransport" = "true" }} }}
    }}]
  }})
}}

resource "aws_iam_role_policy" "p6iamp_{i}" {{
  name = "p6-pol-{i:04d}"
  role = aws_iam_role.p6iam_{i}.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = ["arn:aws:s3:::p6-bucket-{i:04d}/*"]
    }}]
  }})
}}
''',
    },
    "kms": {
        "vuln": '''resource "aws_kms_key" "p6kms_{i}" {{
  description             = "phase6 generated key {i:04d}"
  enable_key_rotation     = false
  deletion_window_in_days = 7
}}
''',
        "secure": '''resource "aws_kms_key" "p6kms_{i}" {{
  description             = "phase6 generated key {i:04d}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}}
''',
    },
    "trail": {
        "vuln": '''resource "aws_cloudtrail" "p6ct_{i}" {{
  name           = "p6-trail-{i:04d}"
  s3_bucket_name = "p6-bucket-{i:04d}"
  is_multi_region_trail = false
  enable_log_file_validation = false
}}
''',
        "secure": '''resource "aws_cloudtrail" "p6ct_{i}" {{
  name           = "p6-trail-{i:04d}"
  s3_bucket_name = "p6-bucket-{i:04d}"
  is_multi_region_trail    = true
  enable_log_file_validation = true
  kms_key_id = aws_kms_key.p6kms_{i}.arn
}}

resource "aws_kms_key" "p6kms_{i}" {{
  description         = "phase6 trail key {i:04d}"
  enable_key_rotation = true
}}
''',
    },
    "ec2": {
        "vuln": '''resource "aws_instance" "p6ec2_{i}" {{
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  metadata_options {{
    http_tokens = "optional"
  }}
}}
''',
        "secure": '''resource "aws_instance" "p6ec2_{i}" {{
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  metadata_options {{
    http_tokens   = "required"
    http_endpoint = "enabled"
  }}
  ebs_optimized = true
}}
''',
    },
    "secret": {
        "vuln": '''resource "aws_secretsmanager_secret" "p6sec_{i}" {{
  name = "p6-secret-{i:04d}"
}}
''',
        "secure": '''resource "aws_secretsmanager_secret" "p6sec_{i}" {{
  name                    = "p6-secret-{i:04d}"
  kms_key_id              = aws_kms_key.p6kms_{i}.arn
}}

resource "aws_kms_key" "p6kms_{i}" {{
  description         = "phase6 secret key {i:04d}"
  enable_key_rotation = true
}}

resource "aws_secretsmanager_secret_rotation" "p6secr_{i}" {{
  secret_id           = aws_secretsmanager_secret.p6sec_{i}.id
  rotation_lambda_arn = "arn:aws:lambda:us-east-1:123456789012:function:p6-rot-{i:04d}"
  rotation_rules {{
    automatically_after_days = 30
  }}
}}
''',
    },
    "sns": {
        "vuln": '''resource "aws_sns_topic" "p6sns_{i}" {{
  name = "p6-topic-{i:04d}"
}}
''',
        "secure": '''resource "aws_sns_topic" "p6sns_{i}" {{
  name              = "p6-topic-{i:04d}"
  kms_master_key_id = aws_kms_key.p6kms_{i}.arn
}}

resource "aws_kms_key" "p6kms_{i}" {{
  description         = "phase6 sns key {i:04d}"
  enable_key_rotation = true
}}
''',
    },
    "ebs": {
        "vuln": '''resource "aws_ebs_volume" "p6ebs_{i}" {{
  availability_zone = "us-east-1a"
  size              = 40
  type              = "gp3"
}}
''',
        "secure": '''resource "aws_ebs_volume" "p6ebs_{i}" {{
  availability_zone = "us-east-1a"
  size              = 40
  type              = "gp3"
  encrypted         = true
  kms_key_id        = aws_kms_key.p6kms_{i}.arn
}}

resource "aws_kms_key" "p6kms_{i}" {{
  description         = "phase6 ebs key {i:04d}"
  enable_key_rotation = true
}}
''',
    },
}

HEADER = """# ---------------------------------------------------------------------------
# Aegis Phase 6 scalability corpus - generated file {idx:04d}/{total:04d}
# generator: docs/audit/raw/phase6/gen_large.py  seed={seed}
# This file is synthetic but structurally representative of real Terraform.
# ---------------------------------------------------------------------------

terraform {{
  required_version = ">= 1.5.0"
  required_providers {{
    aws = {{
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }}
  }}
}}

# --- workload resources -----------------------------------------------------

"""

FOOTER = """
# --- end of generated file --------------------------------------------------
"""

# Deterministic filler so files resemble real modules (~3-5 KiB each).
PAD_LINES = "\n".join(
    f"# filler line {n:02d}: phase6 scalability corpus padding - lorem ipsum dolor sit amet"
    for n in range(40)
)


def gen_file(rng, idx, total, seed):
    n_res = rng.choice([1, 1, 2, 2, 3])  # 1-3 resources, weighted
    keys = rng.sample(sorted(TEMPLATES.keys()), n_res)
    parts = [HEADER.format(idx=idx, total=total, seed=seed)]
    for k in keys:
        variant = "vuln" if rng.random() < 0.60 else "secure"
        parts.append(TEMPLATES[k][variant].format(i=idx))
        parts.append("\n")
    parts.append(FOOTER)
    parts.append(PAD_LINES)
    parts.append("\n")
    return "".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--count", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=SEED)
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    rng = random.Random(args.seed)
    manifest = []
    for idx in range(args.count):
        body = gen_file(rng, idx, args.count, args.seed)
        name = f"p6gen_{idx:04d}.tf"
        path = os.path.join(args.out, name)
        with open(path, "w") as f:
            f.write(body)
        manifest.append((name, hashlib.sha256(body.encode()).hexdigest()))

    with open(args.out + ".MANIFEST.sha256", "w") as f:  # outside corpus dir: not scanned
        for name, h in manifest:
            f.write(f"{h}  {name}\n")
    total_bytes = sum(os.path.getsize(os.path.join(args.out, n)) for n, _ in manifest)
    print(f"wrote {args.count} files to {args.out} ({total_bytes/1048576:.1f} MiB)")


if __name__ == "__main__":
    main()
