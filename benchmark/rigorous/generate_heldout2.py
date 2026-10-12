#!/usr/bin/env python3
"""Generate FRESH held-out corpus with seed 20261012 (never used before)."""
import os, json, random

random.seed(20261012)
BASE = os.path.expanduser("~/workspace/aegis-engine/benchmark/rigorous/heldout2")
os.makedirs(BASE, exist_ok=True)

VULNS = [
    ("s3-unencrypted", 'resource "aws_s3_bucket" "d{i}" {{\n  bucket = "heldout-{i}"\n}}', "encryption"),
    ("sg-open-rdp", 'resource "aws_security_group" "d{i}" {{\n  name = "heldout-{i}"\n  ingress {{\n    from_port = 3389\n    to_port = 3389\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }}\n}}', "network"),
    ("ebs-unencrypted", 'resource "aws_ebs_volume" "d{i}" {{\n  availability_zone = "us-east-1a"\n  size = 50\n}}', "encryption"),
    ("dynamodb-unencrypted", 'resource "aws_dynamodb_table" "d{i}" {{\n  name = "heldout-{i}"\n  billing_mode = "PAY_PER_REQUEST"\n  hash_key = "id"\n  attribute {{\n    name = "id"\n    type = "S"\n  }}\n}}', "encryption"),
    ("sns-unencrypted", 'resource "aws_sns_topic" "d{i}" {{\n  name = "heldout-{i}"\n}}', "encryption"),
]

CLEAN_MAIN = 'resource "aws_s3_bucket" "c{i}" {{\n  bucket = "clean-{i}"\n}}\nresource "aws_s3_bucket_server_side_encryption_configuration" "c{i}" {{\n  bucket = aws_s3_bucket.c{i}.id\n  rule {{\n    apply_server_side_encryption_by_default {{\n      sse_algorithm = "aws:kms"\n      kms_master_key_id = aws_kms_key.c{i}.arn\n    }}\n  }}\n}}\nresource "aws_kms_key" "c{i}" {{\n  description = "clean-{i}"\n  enable_key_rotation = true\n}}\n'

VARIABLES_TF = 'variable "environment" {\n  description = "Deployment environment"\n  type = string\n  default = "dev"\n}\n'

manifest = []
for i in range(150):
    proj = f"h2-{i:03d}"
    pdir = os.path.join(BASE, proj)
    os.makedirs(pdir, exist_ok=True)
    is_vuln = random.random() < 0.65
    expected = []
    
    with open(os.path.join(pdir, "variables.tf"), "w") as f:
        f.write(VARIABLES_TF)
    with open(os.path.join(pdir, "outputs.tf"), "w") as f:
        f.write(f'output "project_id" {{\n  value = "{proj}"\n}}\n')
    
    if is_vuln:
        vid, snippet, cat = random.choice(VULNS)
        with open(os.path.join(pdir, "main.tf"), "w") as f:
            f.write(snippet.format(i=i) + "\n")
        expected.append({"vuln_id": vid, "category": cat})
    else:
        with open(os.path.join(pdir, "main.tf"), "w") as f:
            f.write(CLEAN_MAIN.format(i=i))
        expected.append({"vuln_id": "clean", "category": "clean"})
    
    manifest.append({"project": proj, "vulnerable": is_vuln, "expected": expected})

json.dump(manifest, open(os.path.join(os.path.dirname(BASE), "heldout2_manifest.json"), "w"), indent=2)
v = sum(1 for m in manifest if m["vulnerable"])
print(f"Generated 150 held-out projects (seed 20261012): {v} vulnerable, {150-v} clean")
