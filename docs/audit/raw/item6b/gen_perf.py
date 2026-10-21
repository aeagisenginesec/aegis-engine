#!/usr/bin/env python3
"""Item 6b perf corpora generator (deterministic, seed 20261013).
Mixed providers + modules + deep nesting + large policy docs.
Writes to ~/scratch-item6b/perf/ (disk; /tmp tmpfs is 95% full)."""
import os, random, shutil, sys

BASE = os.path.expanduser("~/scratch-item6b/perf")
R = random.Random(20261013)

S3_VULN = '''resource "aws_s3_bucket" "b{idx}" {{
  bucket = "vuln-{idx}"
}}
resource "aws_s3_bucket_public_access_block" "p{idx}" {{
  bucket = aws_s3_bucket.b{idx}.id
  block_public_acls = false
  block_public_policy = false
  ignore_public_acls = false
  restrict_public_buckets = false
}}
'''
S3_OK = '''resource "aws_s3_bucket" "b{idx}" {{
  bucket = "ok-{idx}"
}}
resource "aws_s3_bucket_public_access_block" "p{idx}" {{
  bucket = aws_s3_bucket.b{idx}.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}}
resource "aws_s3_bucket_server_side_encryption_configuration" "e{idx}" {{
  bucket = aws_s3_bucket.b{idx}.id
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "AES256"
    }}
  }}
}}
'''
SG_VULN = '''resource "aws_security_group" "sg{idx}" {{
  name = "open-{idx}"
  ingress {{
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
  egress {{
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}
'''
AZURE_VULN = '''resource "azurerm_storage_account" "st{idx}" {{
  name = "vulnst{idx}"
  resource_group_name = "rg"
  location = "eastus"
  account_tier = "Standard"
  account_replication_type = "LRS"
  allow_nested_items_to_be_public = true
  min_tls_version = "TLS1_0"
}}
'''
GCP_VULN = '''resource "google_storage_bucket" "g{idx}" {{
  name = "vuln-gcs-{idx}"
  location = "US"
  uniform_bucket_level_access = false
}}
'''
K8S_VULN = '''apiVersion: v1
kind: Pod
metadata:
  name: priv-{idx}
spec:
  hostNetwork: true
  containers:
  - name: c
    image: nginx
    securityContext:
      privileged: true
'''
CFN_VULN = '''AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Bucket{idx}:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: vuln-{idx}
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
'''
ARM_VULN = '''{{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{{
    "type": "Microsoft.Storage/storageAccounts",
    "apiVersion": "2023-01-01",
    "name": "vulnst{idx}",
    "location": "eastus",
    "sku": {{"name": "Standard_LRS"}},
    "kind": "StorageV2",
    "properties": {{"allowBlobPublicAccess": true, "minimumTlsVersion": "TLS1_0"}}
  }}]
}}
'''
BICEP_VULN = '''resource st{idx} 'Microsoft.Storage/storageAccounts@2023-01-01' = {{
  name: 'vulnst{idx}'
  location: 'eastus'
  kind: 'StorageV2'
  sku: {{ name: 'Standard_LRS' }}
  properties: {{ allowBlobPublicAccess: true }}
}}
'''
DOCKER_VULN = '''FROM ubuntu:latest
USER root
RUN echo hello
'''
COMPOSE_VULN = '''services:
  web{idx}:
    image: nginx:latest
    privileged: true
    ports:
      - "80:80"
'''
PULUMI_VULN = '''name: perf{idx}
runtime: yaml
resources:
  bucket{idx}:
    type: aws:s3:Bucket
    properties:
      bucket: vuln-{idx}
'''

TF_TEMPLATES = [S3_VULN, S3_OK, SG_VULN, AZURE_VULN, GCP_VULN]

def tf_file(idx):
    t = R.choice(TF_TEMPLATES)
    return t.format(idx=idx)

def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)

def gen_dir(name, nfiles):
    d = os.path.join(BASE, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for i in range(nfiles):
        kind = i % 10
        if kind <= 5:
            write(f"{d}/tf_{i:04d}.tf", tf_file(i))
        elif kind == 6:
            write(f"{d}/k8s_{i:04d}.yaml", K8S_VULN.format(idx=i))
        elif kind == 7:
            write(f"{d}/cfn_{i:04d}.yaml", CFN_VULN.format(idx=i))
        elif kind == 8:
            write(f"{d}/arm_{i:04d}.json", ARM_VULN.format(idx=i))
        else:
            sub = kind
            if sub == 9:
                # rotate remaining providers
                r = i % 3
                if r == 0:
                    write(f"{d}/bicep_{i:04d}.bicep", BICEP_VULN.format(idx=i))
                elif r == 1:
                    write(f"{d}/Dockerfile.{i:04d}", DOCKER_VULN)
                else:
                    # Pulumi adapter only Handles the exact basename
                    # Pulumi.yaml, so each program gets its own dir.
                    write(f"{d}/pulumi_{i:04d}/Pulumi.yaml", PULUMI_VULN.format(idx=i))
    return d

def gen_modules():
    """Module-heavy repo: root calls 30 modules, each with 2 nested levels."""
    d = os.path.join(BASE, "modules")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    root_calls = []
    for m in range(30):
        root_calls.append(f'module "m{m}" {{ source = "./modules/m{m}" }}\n')
        write(f"{d}/modules/m{m}/main.tf",
              f'resource "aws_s3_bucket" "b{m}" {{ bucket = "mod-{m}" }}\n'
              f'module "sub" {{ source = "./sub" }}\n')
        write(f"{d}/modules/m{m}/sub/main.tf",
              f'resource "aws_security_group" "sg{m}" {{\n  name = "sg-{m}"\n'
              f'  ingress {{ from_port = 22 to_port = 22 protocol = "tcp" cidr_blocks = ["0.0.0.0/0"] }}\n}}\n'
              f'module "leaf" {{ source = "./leaf" }}\n')
        write(f"{d}/modules/m{m}/sub/leaf/main.tf",
              f'resource "aws_s3_bucket" "leaf{m}" {{ bucket = "leaf-{m}" }}\n')
    write(f"{d}/main.tf", "".join(root_calls))
    return d

def gen_deep_policy():
    """Deep nesting (40 levels) + a large IAM policy doc (2000 statements)."""
    d = os.path.join(BASE, "deep-policy")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    stmts = ",\n".join(
        '{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b%d/*"}' % i
        for i in range(2000))
    policy = ('resource "aws_iam_policy" "big" {\n  policy = jsonencode({\n'
              '    Version = "2012-10-17"\n    Statement = [\n' + stmts + '\n    ]\n  })\n}\n')
    nested = 'resource "aws_s3_bucket" "deep" {\n  bucket = "deep"\n  tags = {\n'
    for i in range(40):
        nested += f'    level{i} = {{\n      v = "x"\n'
    nested += '    }\n' * 40 + '  }\n}\n'
    write(f"{d}/policy.tf", policy)
    write(f"{d}/nested.tf", nested)
    return d

if __name__ == "__main__":
    for name, n in [("small", 10), ("medium", 200), ("large", 2000)]:
        print("gen", gen_dir(name, n), n)
    print("gen", gen_modules())
    print("gen", gen_deep_policy())
