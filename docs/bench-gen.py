#!/usr/bin/env python3
"""Generate a large deterministic synthetic Terraform corpus for benchmarking.

Usage: python3 bench-gen.py <outdir> [num_files=500]

Each file gets ~6 resources (S3 / security group / RDS / EC2 mix), half
deliberately misconfigured, half compliant. Seeded RNG => deterministic.
"""
import os
import random
import shutil
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/aegis-bigbench"
NFILES = int(sys.argv[2]) if len(sys.argv) > 2 else 500
RES_PER_FILE = 6

rng = random.Random(20261010)


def s3(i, bad):
    enc = "" if bad else '''
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }'''
    ver = "" if bad else '''
  versioning {
    enabled = true
  }'''
    return f'''resource "aws_s3_bucket" "b{i}" {{
  bucket = "bench-bucket-{i}"{enc}{ver}
}}
'''


def sg(i, bad):
    cidr = '"0.0.0.0/0"' if bad else '"10.0.0.0/8"'
    return f'''resource "aws_security_group" "s{i}" {{
  name = "bench-sg-{i}"

  ingress {{
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [{cidr}]
  }}
}}
'''


def rds(i, bad):
    enc = "false" if bad else "true"
    dp = "false" if bad else "true"
    pub = "true" if bad else "false"
    return f'''resource "aws_db_instance" "d{i}" {{
  identifier          = "bench-db-{i}"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  storage_encrypted   = {enc}
  deletion_protection = {dp}
  publicly_accessible = {pub}
}}
'''


def ec2(i, bad):
    tokens = '"optional"' if bad else '"required"'
    return f'''resource "aws_instance" "e{i}" {{
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  metadata_options {{
    http_tokens = {tokens}
  }}
}}
'''


def main():
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(OUT)
    kinds = [s3, sg, rds, ec2]
    total = 0
    for f in range(NFILES):
        parts = []
        for r in range(RES_PER_FILE):
            kind = kinds[rng.randrange(len(kinds))]
            bad = rng.random() < 0.5
            parts.append(kind(f * RES_PER_FILE + r, bad))
            total += 1
        with open(os.path.join(OUT, f"gen_{f:04d}.tf"), "w") as fh:
            fh.writelines(parts)
    print(f"wrote {NFILES} files, {total} resources to {OUT}")


if __name__ == "__main__":
    main()
