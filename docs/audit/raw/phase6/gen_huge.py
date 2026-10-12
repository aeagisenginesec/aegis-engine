#!/usr/bin/env python3
"""Phase 6 single-huge-file generator.

Builds one Terraform file of a target size by repeating a realistic
multi-resource block with unique names (no dedup ambiguity).

Usage:
    python3 gen_huge.py --out /tmp/p6/huge/huge-under.tf --target-mb 9.5
    python3 gen_huge.py --out /tmp/p6/huge/huge-over.tf  --target-mb 10.6
"""
import argparse
import os

BLOCK = '''# ---- repetition {i} ----
resource "aws_s3_bucket" "p6h_{i}" {{
  bucket = "p6-huge-bucket-{i:06d}"
}}

resource "aws_s3_bucket_versioning" "p6hv_{i}" {{
  bucket = aws_s3_bucket.p6h_{i}.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}

resource "aws_security_group" "p6hg_{i}" {{
  name = "p6-huge-sg-{i:06d}"
  ingress {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }}
  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}

resource "aws_db_instance" "p6hd_{i}" {{
  identifier              = "p6-huge-db-{i:06d}"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "p6-huge-change-me"
  storage_encrypted       = true
  backup_retention_period = 7
}}

'''

HEADER = '# Aegis Phase 6 huge-file corpus - single file near the --max-file-size cap\n\n'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--target-mb", type=float, required=True)
    args = ap.parse_args()
    target = int(args.target_mb * 1048576)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write(HEADER)
        i = 0
        size = len(HEADER)
        while size < target:
            blk = BLOCK.format(i=i)
            f.write(blk)
            size += len(blk)
            i += 1
    actual = os.path.getsize(args.out)
    print(f"wrote {args.out}: {actual} bytes ({actual/1048576:.2f} MiB), {i} blocks")


if __name__ == "__main__":
    main()
