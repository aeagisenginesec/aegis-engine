#!/usr/bin/env python3
"""Round-3 blind corpus generator. FROZEN inputs, seed fixed BEFORE execution.

Methodology notes (written before generation):
- Blind authoring: the author never consulted Aegis rule sources
  (internal/rules/**). Vulnerability patterns come from generic, industry-
  standard IaC security concepts (the same public concept space as round 2).
- Freshness: ids r3001+; content composed fresh for this round. No project
  is copied from docs/audit/raw/final-eval/corpus (round 2).
- 210 projects: terraform 40, cloudformation 30, arm 15, bicep 15,
  pulumi 20 (10 template:-nested + 10 top-level), dockerfile 30,
  compose 25, kubernetes 35.
- Each project = 1-3 assembled blocks. Blocks are natural code snippets.
- The injection plan is written to sealed/injection-plan.json. It is NOT
  ground truth and is NOT consulted during labeling.
- Seed: 20261013.
"""
import json, os, random, shutil

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'corpus')
SEALED = os.path.join(BASE, 'sealed')
SEED = 20261013

# ---------------------------------------------------------------- framework
# A block: dict(name, files(rng, ns) -> {relpath: content}, concepts=[...],
#               secure=bool, desc=str, cloud=str, fmt=str)
BLOCKS = {}

def reg(fmt, name, files, concepts=(), secure=False, desc='', cloud='aws'):
    BLOCKS.setdefault(fmt, []).append({
        'name': name, 'files': files, 'concepts': list(concepts),
        'secure': secure, 'desc': desc, 'cloud': cloud, 'fmt': fmt})

def tf_file(body):
    return lambda rng, ns: {'main.tf': body(rng, ns)}

# unique-ish names per project
def ns_of(pid, rng):
    return {'N': pid.replace('r3', 'r3'),
            'SFX': ''.join(rng.choice('abcdef0123456789') for _ in range(6)),
            'CIDR': f'10.{rng.randint(1,200)}.{rng.randint(0,250)}.0/24',
            'OFFICE': f'203.0.113.{rng.randint(2,250)}/32'}

# ---------------------------------------------------------------- TERRAFORM
def _tf_s3_public(rng, ns):
    return ('resource "aws_s3_bucket" "site" {\n'
            f'  bucket = "site-assets-{ns["SFX"]}"\n'
            '  acl    = "public-read"\n'
            '  website {\n    index_document = "index.html"\n  }\n}\n')
reg('terraform', 'tf_s3_public', tf_file(_tf_s3_public),
    concepts=['s3-public-acl'],
    desc='S3 website bucket with public-read ACL', cloud='aws')

def _tf_s3_policy_public(rng, ns):
    return ('resource "aws_s3_bucket" "data" {\n'
            f'  bucket = "data-lake-{ns["SFX"]}"\n}}\n'
            '\nresource "aws_s3_bucket_policy" "data" {\n'
            '  bucket = aws_s3_bucket.data.id\n'
            '  policy = jsonencode({\n    Version = "2012-10-17"\n'
            '    Statement = [{\n      Effect = "Allow"\n'
            '      Principal = "*"\n'
            '      Action = "s3:GetObject"\n'
            f'      Resource = "arn:aws:s3:::data-lake-{ns["SFX"]}/*"\n'
            '    }]\n  })\n}\n')
reg('terraform', 'tf_s3_policy_public', tf_file(_tf_s3_policy_public),
    concepts=['s3-public-policy'],
    desc='S3 bucket policy granting GetObject to everyone', cloud='aws')

def _tf_s3_secure(rng, ns):
    return ('resource "aws_s3_bucket" "logs" {\n'
            f'  bucket = "app-logs-{ns["SFX"]}"\n}}\n'
            '\nresource "aws_s3_bucket_versioning" "logs" {\n'
            '  bucket = aws_s3_bucket.logs.id\n'
            '  versioning_configuration { status = "Enabled" }\n}\n'
            '\nresource "aws_s3_bucket_server_side_encryption_configuration" "logs" {\n'
            '  bucket = aws_s3_bucket.logs.id\n'
            '  rule {\n    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }\n  }\n}\n'
            '\nresource "aws_s3_bucket_public_access_block" "logs" {\n'
            '  bucket = aws_s3_bucket.logs.id\n'
            '  block_public_acls = true\n  block_public_policy = true\n'
            '  ignore_public_acls = true\n  restrict_public_buckets = true\n}\n')
reg('terraform', 'tf_s3_secure', tf_file(_tf_s3_secure), secure=True,
    desc='S3 bucket with versioning, SSE and public-access block', cloud='aws')

def _tf_sg_ssh_open(rng, ns):
    return ('resource "aws_security_group" "bastion" {\n'
            f'  name = "bastion-{ns["SFX"]}"\n'
            '  ingress {\n    from_port = 22\n    to_port = 22\n'
            '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
            '  egress {\n    from_port = 0\n    to_port = 0\n'
            '    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
reg('terraform', 'tf_sg_ssh_open', tf_file(_tf_sg_ssh_open),
    concepts=['sg-open-ssh'], desc='Security group with SSH open to the internet',
    cloud='aws')

def _tf_sg_all_open(rng, ns):
    return ('resource "aws_security_group" "wide" {\n'
            f'  name = "wide-open-{ns["SFX"]}"\n'
            '  ingress {\n    from_port = 0\n    to_port = 0\n'
            '    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
            '  egress {\n    from_port = 0\n    to_port = 0\n'
            '    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
reg('terraform', 'tf_sg_all_open', tf_file(_tf_sg_all_open),
    concepts=['sg-open-world'], desc='Security group wide open to the internet',
    cloud='aws')

def _tf_sg_db_open(rng, ns):
    return ('resource "aws_security_group" "db" {\n'
            f'  name = "db-{ns["SFX"]}"\n'
            '  ingress {\n    from_port = 5432\n    to_port = 5432\n'
            '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
reg('terraform', 'tf_sg_db_open', tf_file(_tf_sg_db_open),
    concepts=['sg-open-db'], desc='Security group exposing Postgres to the internet',
    cloud='aws')

def _tf_sg_secure(rng, ns):
    return ('resource "aws_security_group" "app" {\n'
            f'  name = "app-{ns["SFX"]}"\n'
            '  ingress {\n    from_port = 22\n    to_port = 22\n'
            '    protocol = "tcp"\n'
            f'    cidr_blocks = ["{ns["OFFICE"]}"]\n  }}\n'
            '  ingress {\n    from_port = 443\n    to_port = 443\n'
            '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
            '  egress {\n    from_port = 0\n    to_port = 0\n'
            '    protocol = "-1"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
reg('terraform', 'tf_sg_secure', tf_file(_tf_sg_secure), secure=True,
    desc='Security group with SSH restricted to office IP', cloud='aws')

def _tf_ec2_no_imds(rng, ns):
    return ('resource "aws_instance" "web" {\n'
            '  ami = "ami-0c55b159cbfafe1f0"\n'
            '  instance_type = "t3.micro"\n'
            f'  tags = {{ Name = "web-{ns["SFX"]}" }}\n}}\n')
reg('terraform', 'tf_ec2_no_imds', tf_file(_tf_ec2_no_imds),
    concepts=['imdsv1'], desc='EC2 instance with IMDSv1 left enabled', cloud='aws')

def _tf_ec2_imdsv2(rng, ns):
    return ('resource "aws_instance" "web" {\n'
            '  ami = "ami-0c55b159cbfafe1f0"\n'
            '  instance_type = "t3.micro"\n'
            '  metadata_options {\n'
            '    http_tokens = "required"\n    http_endpoint = "enabled"\n  }\n'
            f'  tags = {{ Name = "web-{ns["SFX"]}" }}\n}}\n')
reg('terraform', 'tf_ec2_imdsv2', tf_file(_tf_ec2_imdsv2), secure=True,
    desc='EC2 instance enforcing IMDSv2', cloud='aws')

def _tf_ebs_unencrypted(rng, ns):
    return ('resource "aws_instance" "batch" {\n'
            '  ami = "ami-0c55b159cbfafe1f0"\n'
            '  instance_type = "m5.large"\n'
            '  root_block_device {\n    volume_size = 50\n'
            '    encrypted = false\n  }\n'
            f'  tags = {{ Name = "batch-{ns["SFX"]}" }}\n}}\n')
reg('terraform', 'tf_ebs_unencrypted', tf_file(_tf_ebs_unencrypted),
    concepts=['volume-unencrypted'], desc='EC2 root volume explicitly unencrypted',
    cloud='aws')

def _tf_rds_public(rng, ns):
    return ('resource "aws_db_instance" "app" {\n'
            '  engine = "postgres"\n  engine_version = "15.4"\n'
            '  instance_class = "db.t3.micro"\n'
            f'  identifier = "app-{ns["SFX"]}"\n'
            '  allocated_storage = 20\n  storage_encrypted = true\n'
            '  publicly_accessible = true\n'
            '  username = "appadmin"\n'
            f'  password = "Str0ng-{ns["SFX"]}-Db!"\n'
            '  backup_retention_period = 7\n  skip_final_snapshot = true\n}\n')
reg('terraform', 'tf_rds_public', tf_file(_tf_rds_public),
    concepts=['db-public'], desc='RDS instance publicly accessible', cloud='aws')

def _tf_rds_noenc(rng, ns):
    return ('resource "aws_db_instance" "legacy" {\n'
            '  engine = "mysql"\n  engine_version = "8.0"\n'
            '  instance_class = "db.t3.small"\n'
            f'  identifier = "legacy-{ns["SFX"]}"\n'
            '  allocated_storage = 50\n  storage_encrypted = false\n'
            '  publicly_accessible = false\n'
            '  username = "root"\n'
            f'  password = "Str0ng-{ns["SFX"]}-Db!"\n'
            '  backup_retention_period = 7\n  skip_final_snapshot = true\n}\n')
reg('terraform', 'tf_rds_noenc', tf_file(_tf_rds_noenc),
    concepts=['db-no-encryption'], desc='RDS without storage encryption', cloud='aws')

def _tf_rds_nobackup(rng, ns):
    return ('resource "aws_db_instance" "ephemeral" {\n'
            '  engine = "postgres"\n  engine_version = "15.4"\n'
            '  instance_class = "db.t3.micro"\n'
            f'  identifier = "ephemeral-{ns["SFX"]}"\n'
            '  allocated_storage = 20\n  storage_encrypted = true\n'
            '  publicly_accessible = false\n'
            '  username = "appadmin"\n'
            f'  password = "Str0ng-{ns["SFX"]}-Db!"\n'
            '  backup_retention_period = 0\n  skip_final_snapshot = true\n}\n')
reg('terraform', 'tf_rds_nobackup', tf_file(_tf_rds_nobackup),
    concepts=['db-no-backup'], desc='RDS with automated backups disabled', cloud='aws')

def _tf_rds_weakpw(rng, ns):
    return ('resource "aws_db_instance" "dev" {\n'
            '  engine = "postgres"\n  engine_version = "15.4"\n'
            '  instance_class = "db.t3.micro"\n'
            f'  identifier = "dev-{ns["SFX"]}"\n'
            '  allocated_storage = 20\n  storage_encrypted = true\n'
            '  publicly_accessible = false\n'
            '  username = "postgres"\n'
            '  password = "password123"\n'
            '  backup_retention_period = 7\n  skip_final_snapshot = true\n}\n')
reg('terraform', 'tf_rds_weakpw', tf_file(_tf_rds_weakpw),
    concepts=['db-weak-auth'], desc='RDS with weak default master password', cloud='aws')

def _tf_rds_secure(rng, ns):
    return ('resource "aws_db_instance" "prod" {\n'
            '  engine = "postgres"\n  engine_version = "15.4"\n'
            '  instance_class = "db.t3.medium"\n'
            f'  identifier = "prod-{ns["SFX"]}"\n'
            '  allocated_storage = 100\n  storage_encrypted = true\n'
            '  publicly_accessible = false\n'
            '  username = "appadmin"\n'
            f'  password = "Str0ng-{ns["SFX"]}-Db!"\n'
            '  backup_retention_period = 14\n'
            '  deletion_protection = true\n'
            '  multi_az = true\n  skip_final_snapshot = false\n}\n')
reg('terraform', 'tf_rds_secure', tf_file(_tf_rds_secure), secure=True,
    desc='RDS with encryption, backups and deletion protection', cloud='aws')

def _tf_iam_wildcard(rng, ns):
    return ('resource "aws_iam_user" "deployer" {\n'
            f'  name = "deployer-{ns["SFX"]}"\n}}\n'
            '\nresource "aws_iam_user_policy" "deployer" {\n'
            '  user = aws_iam_user.deployer.name\n'
            '  policy = jsonencode({\n    Version = "2012-10-17"\n'
            '    Statement = [{\n      Effect = "Allow"\n'
            '      Action = "*"\n      Resource = "*"\n    }]\n  })\n}\n')
reg('terraform', 'tf_iam_wildcard', tf_file(_tf_iam_wildcard),
    concepts=['iam-wildcard'], desc='IAM user with wildcard action on all resources',
    cloud='aws')

def _tf_iam_admin(rng, ns):
    return ('resource "aws_iam_user" "ops" {\n'
            f'  name = "ops-{ns["SFX"]}"\n}}\n'
            '\nresource "aws_iam_user_policy_attachment" "ops" {\n'
            '  user = aws_iam_user.ops.name\n'
            '  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n}\n')
reg('terraform', 'tf_iam_admin', tf_file(_tf_iam_admin),
    concepts=['iam-admin'], desc='IAM user with AdministratorAccess', cloud='aws')

def _tf_iam_trust_broad(rng, ns):
    return ('resource "aws_iam_role" "partner" {\n'
            f'  name = "partner-{ns["SFX"]}"\n'
            '  assume_role_policy = jsonencode({\n'
            '    Version = "2012-10-17"\n'
            '    Statement = [{\n      Effect = "Allow"\n'
            '      Principal = { AWS = "*" }\n'
            '      Action = "sts:AssumeRole"\n    }]\n  })\n}\n')
reg('terraform', 'tf_iam_trust_broad', tf_file(_tf_iam_trust_broad),
    concepts=['iam-trust-broad'], desc='IAM role trust policy open to any AWS principal',
    cloud='aws')

def _tf_iam_secure(rng, ns):
    return ('resource "aws_iam_user" "reader" {\n'
            f'  name = "reader-{ns["SFX"]}"\n}}\n'
            '\nresource "aws_iam_user_policy" "reader" {\n'
            '  user = aws_iam_user.reader.name\n'
            '  policy = jsonencode({\n    Version = "2012-10-17"\n'
            '    Statement = [{\n      Effect = "Allow"\n'
              '      Action = ["s3:GetObject", "s3:ListBucket"]\n'
            '      Resource = ["arn:aws:s3:::reports-' + ns["SFX"] + '",\n'
            '       "arn:aws:s3:::reports-' + ns["SFX"] + '/*"]\n    }]\n  })\n}\n')
reg('terraform', 'tf_iam_secure', tf_file(_tf_iam_secure), secure=True,
    desc='IAM user with scoped read-only policy', cloud='aws')

def _tf_secret_var(rng, ns):
    return ('variable "db_password" {\n'
            '  type = string\n'
            '  default = "Sup3rSecret!-prod-2024"\n'
            '  description = "Database master password"\n}\n'
            '\nresource "aws_db_instance" "app" {\n'
            '  engine = "postgres"\n  engine_version = "15.4"\n'
            '  instance_class = "db.t3.micro"\n'
            f'  identifier = "app-{ns["SFX"]}"\n'
            '  allocated_storage = 20\n  storage_encrypted = true\n'
            '  username = "appadmin"\n  password = var.db_password\n'
            '  skip_final_snapshot = true\n}\n')
reg('terraform', 'tf_secret_var', tf_file(_tf_secret_var),
    concepts=['secret-hardcoded'], desc='Database password hardcoded as variable default',
    cloud='aws')

def _tf_lambda_url_public(rng, ns):
    return ('resource "aws_lambda_function" "hook" {\n'
            f'  function_name = "hook-{ns["SFX"]}"\n'
            '  role = "arn:aws:iam::123456789012:role/lambda-exec"\n'
            '  runtime = "python3.11"\n  handler = "index.handler"\n'
            '  filename = "hook.zip"\n}\n'
            '\nresource "aws_lambda_function_url" "hook" {\n'
            '  function_name = aws_lambda_function.hook.function_name\n'
            '  authorization_type = "NONE"\n}\n')
reg('terraform', 'tf_lambda_url_public', tf_file(_tf_lambda_url_public),
    concepts=['lambda-public-url'], desc='Lambda function URL with no auth', cloud='aws')

def _tf_kms_no_rotation(rng, ns):
    return ('resource "aws_kms_key" "data" {\n'
            f'  description = "data-key-{ns["SFX"]}"\n'
            '  enable_key_rotation = false\n}\n'
            '\nresource "aws_s3_bucket" "vault" {\n'
            f'  bucket = "vault-{ns["SFX"]}"\n}}\n'
            '\nresource "aws_s3_bucket_server_side_encryption_configuration" "vault" {\n'
            '  bucket = aws_s3_bucket.vault.id\n'
            '  rule {\n'
            '    apply_server_side_encryption_by_default {\n'
            '      sse_algorithm = "aws:kms"\n'
            '      kms_master_key_id = aws_kms_key.data.arn\n    }\n  }\n}\n')
reg('terraform', 'tf_kms_no_rotation', tf_file(_tf_kms_no_rotation),
    concepts=['kms-no-rotation'], desc='KMS key with rotation disabled', cloud='aws')

def _tf_eks_public(rng, ns):
    return ('resource "aws_eks_cluster" "main" {\n'
            f'  name = "main-{ns["SFX"]}"\n'
            '  role_arn = "arn:aws:iam::123456789012:role/eks-cluster"\n'
            '  vpc_config {\n'
            '    subnet_ids = ["subnet-aaa", "subnet-bbb"]\n'
            '    endpoint_public_access = true\n'
            '    public_access_cidrs = ["0.0.0.0/0"]\n  }\n}\n')
reg('terraform', 'tf_eks_public', tf_file(_tf_eks_public),
    concepts=['eks-public-api'], desc='EKS cluster API endpoint public to the internet',
    cloud='aws')

# --- GCP terraform blocks ---
def _tf_gcs_public(rng, ns):
    return ('resource "google_storage_bucket" "assets" {\n'
            f'  name = "assets-{ns["SFX"]}"\n'
            '  location = "US"\n}\n'
            '\nresource "google_storage_bucket_iam_member" "public" {\n'
            '  bucket = google_storage_bucket.assets.name\n'
            '  role = "roles/storage.objectViewer"\n'
            '  member = "allUsers"\n}\n')
reg('terraform', 'tf_gcs_public', tf_file(_tf_gcs_public),
    concepts=['gcs-public'], desc='GCS bucket readable by allUsers', cloud='gcp')

def _tf_gcs_no_cmek(rng, ns):
    return ('resource "google_storage_bucket" "data" {\n'
            f'  name = "data-{ns["SFX"]}"\n'
            '  location = "EU"\n  uniform_bucket_level_access = true\n}\n')
reg('terraform', 'tf_gcs_no_cmek', tf_file(_tf_gcs_no_cmek),
    concepts=['gcp-bucket-no-cmek'],
    desc='GCS bucket without customer-managed encryption key', cloud='gcp')

def _tf_sql_public(rng, ns):
    return ('resource "google_sql_database_instance" "main" {\n'
            f'  name = "main-{ns["SFX"]}"\n'
            '  database_version = "POSTGRES_15"\n'
            '  region = "europe-west1"\n'
            '  settings {\n    tier = "db-f1-micro"\n'
            '    ip_configuration {\n'
            '      ipv4_enabled = true\n'
            '      authorized_networks { name = "world"  value = "0.0.0.0/0" }\n'
            '    }\n  }\n}\n')
reg('terraform', 'tf_sql_public', tf_file(_tf_sql_public),
    concepts=['gcp-sql-public'], desc='Cloud SQL open to the internet', cloud='gcp')

def _tf_vm_ipforward(rng, ns):
    return ('resource "google_compute_instance" "nat" {\n'
            f'  name = "nat-{ns["SFX"]}"\n'
            '  machine_type = "e2-medium"\n  zone = "europe-west1-b"\n'
            '  can_ip_forward = true\n'
            '  boot_disk {\n    initialize_params { image = "debian-cloud/debian-12" }\n  }\n'
            '  network_interface { network = "default"\n'
            '    access_config {}\n  }\n}\n')
reg('terraform', 'tf_vm_ipforward', tf_file(_tf_vm_ipforward),
    concepts=['gcp-compute-ip-forward'], desc='GCE VM with IP forwarding enabled',
    cloud='gcp')

def _tf_gke_public(rng, ns):
    return ('resource "google_container_cluster" "main" {\n'
            f'  name = "main-{ns["SFX"]}"\n'
            '  location = "europe-west1"\n'
            '  initial_node_count = 1\n'
            '  master_authorized_networks_config {}\n}\n')
reg('terraform', 'tf_gke_public', tf_file(_tf_gke_public),
    concepts=['gcp-gke-public'], desc='GKE cluster with public control plane',
    cloud='gcp')

# --- Azure terraform blocks ---
def _tf_az_storage_public(rng, ns):
    return ('resource "azurerm_storage_account" "data" {\n'
            f'  name = "data{ns["SFX"]}"\n'
            '  resource_group_name = "rg-data"\n'
            '  location = "westeurope"\n'
            '  account_tier = "Standard"\n'
            '  account_replication_type = "LRS"\n'
            '  allow_blob_public_access = true\n'
            '  min_tls_version = "TLS1_2"\n}\n')
reg('terraform', 'tf_az_storage_public', tf_file(_tf_az_storage_public),
    concepts=['storage-public-azure'], desc='Storage account allowing public blob access',
    cloud='azure')

def _tf_az_storage_weak_tls(rng, ns):
    return ('resource "azurerm_storage_account" "legacy" {\n'
            f'  name = "legacy{ns["SFX"]}"\n'
            '  resource_group_name = "rg-legacy"\n'
            '  location = "westeurope"\n'
            '  account_tier = "Standard"\n'
            '  account_replication_type = "LRS"\n'
            '  allow_blob_public_access = false\n'
            '  min_tls_version = "TLS1_0"\n}\n')
reg('terraform', 'tf_az_storage_weak_tls', tf_file(_tf_az_storage_weak_tls),
    concepts=['weak-tls'], desc='Storage account allowing TLS 1.0', cloud='azure')

def _tf_az_keyvault_nopurge(rng, ns):
    return ('resource "azurerm_key_vault" "main" {\n'
            f'  name = "kv-{ns["SFX"]}"\n'
            '  location = "westeurope"\n'
            '  resource_group_name = "rg-kv"\n'
            '  sku_name = "standard"\n'
            '  tenant_id = "00000000-0000-0000-0000-000000000000"\n'
            '  purge_protection_enabled = false\n'
            '  soft_delete_retention_days = 7\n}\n')
reg('terraform', 'tf_az_keyvault_nopurge', tf_file(_tf_az_keyvault_nopurge),
    concepts=['keyvault-no-purge'], desc='Key Vault without purge protection',
    cloud='azure')

def _tf_az_nsg_open(rng, ns):
    return ('resource "azurerm_network_security_group" "web" {\n'
            f'  name = "web-{ns["SFX"]}"\n'
            '  location = "westeurope"\n'
            '  resource_group_name = "rg-web"\n'
            '  security_rule {\n'
            '    name = "ssh"\n    priority = 100\n'
            '    direction = "Inbound"\n    access = "Allow"\n'
            '    protocol = "Tcp"\n'
            '    source_port_range = "*"\n'
            '    destination_port_range = "22"\n'
            '    source_address_prefix = "*"\n'
            '    destination_address_prefix = "*"\n  }\n}\n')
reg('terraform', 'tf_az_nsg_open', tf_file(_tf_az_nsg_open),
    concepts=['nsg-open'], desc='NSG allowing SSH from any source', cloud='azure')

def _tf_az_secure(rng, ns):
    return ('resource "azurerm_storage_account" "data" {\n'
            f'  name = "data{ns["SFX"]}"\n'
            '  resource_group_name = "rg-data"\n'
            '  location = "westeurope"\n'
            '  account_tier = "Standard"\n'
            '  account_replication_type = "LRS"\n'
            '  allow_blob_public_access = false\n'
            '  min_tls_version = "TLS1_2"\n}\n'
            '\nresource "azurerm_key_vault" "main" {\n'
            f'  name = "kv-{ns["SFX"]}"\n'
            '  location = "westeurope"\n'
            '  resource_group_name = "rg-kv"\n'
            '  sku_name = "standard"\n'
            '  tenant_id = "00000000-0000-0000-0000-000000000000"\n'
            '  purge_protection_enabled = true\n'
            '  soft_delete_retention_days = 90\n}\n')
reg('terraform', 'tf_az_secure', tf_file(_tf_az_secure), secure=True,
    desc='Hardened storage account and key vault', cloud='azure')

# ---------------------------------------------------------------- CLOUDFORMATION (YAML)
def cfn_file(body):
    return lambda rng, ns: {'template.yaml': body(rng, ns)}

def _cfn_hdr(ns, desc):
    return (f'AWSTemplateFormatVersion: "2010-09-09"\n'
            f'Description: {desc}\nResources:\n')

def _cfn_s3_public(rng, ns):
    return (_cfn_hdr(ns, 'Public website bucket')
            + '  SiteBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n'
            f'      BucketName: site-{ns["SFX"]}\n'
            '      AccessControl: PublicRead\n'
            '      WebsiteConfiguration:\n'
            '        IndexDocument: index.html\n')
reg('cloudformation', 'cfn_s3_public', cfn_file(_cfn_s3_public),
    concepts=['s3-public-acl'], desc='CFN S3 bucket with PublicRead ACL', cloud='aws')

def _cfn_s3_policy_public(rng, ns):
    return (_cfn_hdr(ns, 'Bucket with open policy')
            + '  DataBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n'
            f'      BucketName: data-{ns["SFX"]}\n'
            '  DataPolicy:\n    Type: AWS::S3::BucketPolicy\n'
            '    Properties:\n      Bucket: !Ref DataBucket\n'
            '      PolicyDocument:\n        Version: "2012-10-17"\n'
            '        Statement:\n          - Effect: Allow\n'
            '            Principal: "*"\n'
            '            Action: s3:GetObject\n'
            f'            Resource: arn:aws:s3:::data-{ns["SFX"]}/*\n')
reg('cloudformation', 'cfn_s3_policy_public', cfn_file(_cfn_s3_policy_public),
    concepts=['s3-public-policy'], desc='CFN S3 bucket policy open to everyone',
    cloud='aws')

def _cfn_s3_secure(rng, ns):
    return (_cfn_hdr(ns, 'Hardened bucket')
            + '  LogsBucket:\n    Type: AWS::S3::Bucket\n    Properties:\n'
            f'      BucketName: logs-{ns["SFX"]}\n'
            '      VersioningConfiguration:\n        Status: Enabled\n'
            '      BucketEncryption:\n'
            '        ServerSideEncryptionConfiguration:\n'
            '          - ServerSideEncryptionByDefault:\n'
            '              SSEAlgorithm: AES256\n'
            '      PublicAccessBlockConfiguration:\n'
            '        BlockPublicAcls: true\n        BlockPublicPolicy: true\n'
            '        IgnorePublicAcls: true\n        RestrictPublicBuckets: true\n')
reg('cloudformation', 'cfn_s3_secure', cfn_file(_cfn_s3_secure), secure=True,
    desc='CFN hardened S3 bucket', cloud='aws')

def _cfn_sg_ssh_open(rng, ns):
    return (_cfn_hdr(ns, 'Bastion security group')
            + '  BastionSG:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n'
            f'      GroupName: bastion-{ns["SFX"]}\n'
            '      GroupDescription: bastion access\n'
            '      SecurityGroupIngress:\n'
            '        - IpProtocol: tcp\n          FromPort: 22\n          ToPort: 22\n'
            '          CidrIp: 0.0.0.0/0\n')
reg('cloudformation', 'cfn_sg_ssh_open', cfn_file(_cfn_sg_ssh_open),
    concepts=['sg-open-ssh'], desc='CFN SG with SSH open to the world', cloud='aws')

def _cfn_sg_all_open(rng, ns):
    return (_cfn_hdr(ns, 'Permissive security group')
            + '  WideSG:\n    Type: AWS::EC2::SecurityGroup\n    Properties:\n'
            f'      GroupName: wide-{ns["SFX"]}\n'
            '      GroupDescription: overly permissive\n'
            '      SecurityGroupIngress:\n'
            '        - IpProtocol: "-1"\n          CidrIp: 0.0.0.0/0\n')
reg('cloudformation', 'cfn_sg_all_open', cfn_file(_cfn_sg_all_open),
    concepts=['sg-open-world'], desc='CFN SG open to the internet on all ports',
    cloud='aws')

def _cfn_ec2_no_imds(rng, ns):
    return (_cfn_hdr(ns, 'Web server')
            + '  WebServer:\n    Type: AWS::EC2::Instance\n    Properties:\n'
            '      ImageId: ami-0c55b159cbfafe1f0\n'
            '      InstanceType: t3.micro\n'
            f'      Tags: [{chr(123)}Key: Name, Value: web-{ns["SFX"]}{chr(125)}]\n')
reg('cloudformation', 'cfn_ec2_no_imds', cfn_file(_cfn_ec2_no_imds),
    concepts=['imdsv1'], desc='CFN EC2 with IMDSv1 enabled', cloud='aws')

def _cfn_ec2_imdsv2(rng, ns):
    return (_cfn_hdr(ns, 'Hardened web server')
            + '  WebServer:\n    Type: AWS::EC2::Instance\n    Properties:\n'
            '      ImageId: ami-0c55b159cbfafe1f0\n'
            '      InstanceType: t3.micro\n'
            '      MetadataOptions:\n        HttpTokens: required\n'
            '        HttpEndpoint: enabled\n'
            f'      Tags: [{chr(123)}Key: Name, Value: web-{ns["SFX"]}{chr(125)}]\n')
reg('cloudformation', 'cfn_ec2_imdsv2', cfn_file(_cfn_ec2_imdsv2), secure=True,
    desc='CFN EC2 enforcing IMDSv2', cloud='aws')

def _cfn_rds_public(rng, ns):
    return (_cfn_hdr(ns, 'App database')
            + '  AppDB:\n    Type: AWS::RDS::DBInstance\n    Properties:\n'
            '      Engine: postgres\n      EngineVersion: "15.4"\n'
            '      DBInstanceClass: db.t3.micro\n'
            f'      DBInstanceIdentifier: app-{ns["SFX"]}\n'
            '      AllocatedStorage: "20"\n'
            '      StorageEncrypted: true\n'
            '      PubliclyAccessible: true\n'
            '      MasterUsername: appadmin\n'
            f'      MasterUserPassword: Str0ng-{ns["SFX"]}-Db!\n'
            '      BackupRetentionPeriod: 7\n')
reg('cloudformation', 'cfn_rds_public', cfn_file(_cfn_rds_public),
    concepts=['db-public'], desc='CFN RDS publicly accessible', cloud='aws')

def _cfn_rds_noenc(rng, ns):
    return (_cfn_hdr(ns, 'Legacy database')
            + '  LegacyDB:\n    Type: AWS::RDS::DBInstance\n    Properties:\n'
            '      Engine: mysql\n      EngineVersion: "8.0"\n'
            '      DBInstanceClass: db.t3.small\n'
            f'      DBInstanceIdentifier: legacy-{ns["SFX"]}\n'
            '      AllocatedStorage: "50"\n'
            '      StorageEncrypted: false\n'
            '      PubliclyAccessible: false\n'
            '      MasterUsername: root\n'
            f'      MasterUserPassword: Str0ng-{ns["SFX"]}-Db!\n'
            '      BackupRetentionPeriod: 7\n')
reg('cloudformation', 'cfn_rds_noenc', cfn_file(_cfn_rds_noenc),
    concepts=['db-no-encryption'], desc='CFN RDS without storage encryption',
    cloud='aws')

def _cfn_rds_secure(rng, ns):
    return (_cfn_hdr(ns, 'Production database')
            + '  ProdDB:\n    Type: AWS::RDS::DBInstance\n    Properties:\n'
            '      Engine: postgres\n      EngineVersion: "15.4"\n'
            '      DBInstanceClass: db.t3.medium\n'
            f'      DBInstanceIdentifier: prod-{ns["SFX"]}\n'
            '      AllocatedStorage: "100"\n'
            '      StorageEncrypted: true\n'
            '      PubliclyAccessible: false\n'
            '      MasterUsername: appadmin\n'
            f'      MasterUserPassword: Str0ng-{ns["SFX"]}-Db!\n'
            '      BackupRetentionPeriod: 14\n'
            '      DeletionProtection: true\n      MultiAZ: true\n')
reg('cloudformation', 'cfn_rds_secure', cfn_file(_cfn_rds_secure), secure=True,
    desc='CFN hardened RDS', cloud='aws')

def _cfn_iam_wildcard(rng, ns):
    return (_cfn_hdr(ns, 'Deployer user')
            + '  Deployer:\n    Type: AWS::IAM::User\n    Properties:\n'
            f'      UserName: deployer-{ns["SFX"]}\n'
            '  DeployerPolicy:\n    Type: AWS::IAM::Policy\n    Properties:\n'
            '      PolicyName: deployer-policy\n'
            '      Users: [!Ref Deployer]\n'
            '      PolicyDocument:\n        Version: "2012-10-17"\n'
            '        Statement:\n          - Effect: Allow\n'
            '            Action: "*"\n            Resource: "*"\n')
reg('cloudformation', 'cfn_iam_wildcard', cfn_file(_cfn_iam_wildcard),
    concepts=['iam-wildcard'], desc='CFN IAM wildcard policy', cloud='aws')

def _cfn_iam_admin(rng, ns):
    return (_cfn_hdr(ns, 'Ops user')
            + '  OpsUser:\n    Type: AWS::IAM::User\n    Properties:\n'
            f'      UserName: ops-{ns["SFX"]}\n'
            '  OpsAdmin:\n    Type: AWS::IAM::ManagedPolicy\n    Properties:\n'
            '      ManagedPolicyName: ops-admin\n'
            '      Users: [!Ref OpsUser]\n'
            '      PolicyDocument:\n        Version: "2012-10-17"\n'
            '        Statement:\n          - Effect: Allow\n'
            '            Action: "*"\n            Resource: "*"\n')
reg('cloudformation', 'cfn_iam_admin', cfn_file(_cfn_iam_admin),
    concepts=['iam-admin'], desc='CFN IAM user with full admin rights', cloud='aws')

def _cfn_secret_param(rng, ns):
    return (_cfn_hdr(ns, 'App stack')
            + 'Parameters:\n'
            '  DbPassword:\n    Type: String\n'
            '    Default: Sup3rSecret!-prod-2024\n'
            '    Description: Database password\n'
            'Resources:\n'
            '  AppDB:\n    Type: AWS::RDS::DBInstance\n    Properties:\n'
            '      Engine: postgres\n      DBInstanceClass: db.t3.micro\n'
            f'      DBInstanceIdentifier: app-{ns["SFX"]}\n'
            '      AllocatedStorage: "20"\n'
            '      StorageEncrypted: true\n'
            '      MasterUsername: appadmin\n'
            '      MasterUserPassword: !Ref DbPassword\n')
reg('cloudformation', 'cfn_secret_param', cfn_file(_cfn_secret_param),
    concepts=['secret-hardcoded'], desc='CFN parameter with hardcoded default password',
    cloud='aws')

def _cfn_ebs_unencrypted(rng, ns):
    return (_cfn_hdr(ns, 'Batch server')
            + '  BatchServer:\n    Type: AWS::EC2::Instance\n    Properties:\n'
            '      ImageId: ami-0c55b159cbfafe1f0\n'
            '      InstanceType: m5.large\n'
            '      BlockDeviceMappings:\n'
            '        - DeviceName: /dev/sda1\n'
            '          Ebs:\n            VolumeSize: 50\n'
            '            Encrypted: false\n')
reg('cloudformation', 'cfn_ebs_unencrypted', cfn_file(_cfn_ebs_unencrypted),
    concepts=['volume-unencrypted'], desc='CFN EC2 with unencrypted root volume',
    cloud='aws')

def _cfn_kms_no_rotation(rng, ns):
    return (_cfn_hdr(ns, 'Data key')
            + '  DataKey:\n    Type: AWS::KMS::Key\n    Properties:\n'
            f'      Description: data-key-{ns["SFX"]}\n'
            '      EnableKeyRotation: false\n'
            '      KeyPolicy:\n        Version: "2012-10-17"\n'
            '        Statement:\n          - Effect: Allow\n'
            '            Principal:\n              AWS: !Sub arn:aws:iam::${AWS::AccountId}:root\n'
            '            Action: kms:*\n            Resource: "*"\n')
reg('cloudformation', 'cfn_kms_no_rotation', cfn_file(_cfn_kms_no_rotation),
    concepts=['kms-no-rotation'], desc='CFN KMS key without rotation', cloud='aws')

def _cfn_lambda_url_public(rng, ns):
    return (_cfn_hdr(ns, 'Webhook function')
            + '  HookFn:\n    Type: AWS::Lambda::Function\n    Properties:\n'
            f'      FunctionName: hook-{ns["SFX"]}\n'
            '      Role: arn:aws:iam::123456789012:role/lambda-exec\n'
            '      Runtime: python3.11\n      Handler: index.handler\n'
            '      Code:\n        ZipFile: "def handler(e, c): return {}"\n'
            '  HookUrl:\n    Type: AWS::Lambda::Url\n    Properties:\n'
            '      TargetFunctionArn: !GetAtt HookFn.Arn\n'
            '      AuthType: NONE\n')
reg('cloudformation', 'cfn_lambda_url_public', cfn_file(_cfn_lambda_url_public),
    concepts=['lambda-public-url'], desc='CFN Lambda URL without auth', cloud='aws')

def _cfn_eks_public(rng, ns):
    return (_cfn_hdr(ns, 'EKS cluster')
            + '  MainCluster:\n    Type: AWS::EKS::Cluster\n    Properties:\n'
            f'      Name: main-{ns["SFX"]}\n'
            '      RoleArn: arn:aws:iam::123456789012:role/eks-cluster\n'
            '      ResourcesVpcConfig:\n'
            '        SubnetIds: [subnet-aaa, subnet-bbb]\n'
            '        EndpointPublicAccess: true\n')
reg('cloudformation', 'cfn_eks_public', cfn_file(_cfn_eks_public),
    concepts=['eks-public-api'], desc='CFN EKS with public API endpoint', cloud='aws')

# ---------------------------------------------------------------- ARM (JSON)
def arm_file(body):
    return lambda rng, ns: {'azuredeploy.json': body(rng, ns)}

def _arm_hdr():
    return ('{\n  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",\n'
            '  "contentVersion": "1.0.0.0",\n  "resources": [\n')

def _arm_storage_public(rng, ns):
    return (_arm_hdr()
            + '    {\n      "type": "Microsoft.Storage/storageAccounts",\n'
            '      "apiVersion": "2023-01-01",\n'
            f'      "name": "data{ns["SFX"]}",\n'
            '      "location": "westeurope",\n      "kind": "StorageV2",\n'
            '      "sku": { "name": "Standard_LRS" },\n'
            '      "properties": {\n'
            '        "allowBlobPublicAccess": true,\n'
            '        "minimumTlsVersion": "TLS1_2",\n'
            '        "supportsHttpsTrafficOnly": true\n      }\n    }\n  ]\n}\n')
reg('arm', 'arm_storage_public', arm_file(_arm_storage_public),
    concepts=['storage-public-azure'], desc='ARM storage account with public blob access',
    cloud='azure')

def _arm_storage_weak_tls(rng, ns):
    return (_arm_hdr()
            + '    {\n      "type": "Microsoft.Storage/storageAccounts",\n'
            '      "apiVersion": "2023-01-01",\n'
            f'      "name": "legacy{ns["SFX"]}",\n'
            '      "location": "westeurope",\n      "kind": "StorageV2",\n'
            '      "sku": { "name": "Standard_LRS" },\n'
            '      "properties": {\n'
            '        "allowBlobPublicAccess": false,\n'
            '        "minimumTlsVersion": "TLS1_0",\n'
            '        "supportsHttpsTrafficOnly": true\n      }\n    }\n  ]\n}\n')
reg('arm', 'arm_storage_weak_tls', arm_file(_arm_storage_weak_tls),
    concepts=['weak-tls'], desc='ARM storage account with TLS 1.0', cloud='azure')

def _arm_nsg_open(rng, ns):
    return (_arm_hdr()
            + '    {\n      "type": "Microsoft.Network/networkSecurityGroups",\n'
            '      "apiVersion": "2023-05-01",\n'
            f'      "name": "web-{ns["SFX"]}",\n'
            '      "location": "westeurope",\n'
            '      "properties": {\n        "securityRules": [\n'
            '          {\n            "name": "allow-ssh",\n'
            '            "properties": {\n'
            '              "priority": 100,\n              "direction": "Inbound",\n'
            '              "access": "Allow",\n              "protocol": "Tcp",\n'
            '              "sourcePortRange": "*",\n'
            '              "destinationPortRange": "22",\n'
            '              "sourceAddressPrefix": "*",\n'
            '              "destinationAddressPrefix": "*"\n'
            '            }\n          }\n        ]\n      }\n    }\n  ]\n}\n')
reg('arm', 'arm_nsg_open', arm_file(_arm_nsg_open),
    concepts=['nsg-open'], desc='ARM NSG allowing SSH from anywhere', cloud='azure')

def _arm_keyvault_nopurge(rng, ns):
    return (_arm_hdr()
            + '    {\n      "type": "Microsoft.KeyVault/vaults",\n'
            '      "apiVersion": "2023-07-01",\n'
            f'      "name": "kv-{ns["SFX"]}",\n'
            '      "location": "westeurope",\n'
            '      "properties": {\n'
            '        "sku": { "family": "A", "name": "standard" },\n'
            '        "tenantId": "00000000-0000-0000-0000-000000000000",\n'
            '        "enablePurgeProtection": false,\n'
            '        "enableSoftDelete": true,\n'
            '        "accessPolicies": []\n      }\n    }\n  ]\n}\n')
reg('arm', 'arm_keyvault_nopurge', arm_file(_arm_keyvault_nopurge),
    concepts=['keyvault-no-purge'], desc='ARM Key Vault without purge protection',
    cloud='azure')

def _arm_secure(rng, ns):
    return (_arm_hdr()
            + '    {\n      "type": "Microsoft.Storage/storageAccounts",\n'
            '      "apiVersion": "2023-01-01",\n'
            f'      "name": "data{ns["SFX"]}",\n'
            '      "location": "westeurope",\n      "kind": "StorageV2",\n'
            '      "sku": { "name": "Standard_LRS" },\n'
            '      "properties": {\n'
            '        "allowBlobPublicAccess": false,\n'
            '        "minimumTlsVersion": "TLS1_2",\n'
            '        "supportsHttpsTrafficOnly": true\n      }\n    },\n'
            '    {\n      "type": "Microsoft.KeyVault/vaults",\n'
            '      "apiVersion": "2023-07-01",\n'
            f'      "name": "kv-{ns["SFX"]}",\n'
            '      "location": "westeurope",\n'
            '      "properties": {\n'
            '        "sku": { "family": "A", "name": "standard" },\n'
            '        "tenantId": "00000000-0000-0000-0000-000000000000",\n'
            '        "enablePurgeProtection": true,\n'
            '        "enableSoftDelete": true,\n'
            '        "accessPolicies": []\n      }\n    }\n  ]\n}\n')
reg('arm', 'arm_secure', arm_file(_arm_secure), secure=True,
    desc='ARM hardened storage + key vault', cloud='azure')

# ---------------------------------------------------------------- BICEP
def bicep_file(body):
    return lambda rng, ns: {'main.bicep': body(rng, ns)}

def _bicep_storage_public(rng, ns):
    return (f"resource data 'Microsoft.Storage/storageAccounts@2023-01-01' = {{\n"
            f"  name: 'data{ns['SFX']}'\n"
            "  location: 'westeurope'\n  kind: 'StorageV2'\n"
            "  sku: { name: 'Standard_LRS' }\n  properties: {\n"
            "    allowBlobPublicAccess: true\n"
            "    minimumTlsVersion: 'TLS1_2'\n"
            "    supportsHttpsTrafficOnly: true\n  }\n}\n")
reg('bicep', 'bicep_storage_public', bicep_file(_bicep_storage_public),
    concepts=['storage-public-azure'], desc='Bicep storage with public blob access',
    cloud='azure')

def _bicep_storage_weak_tls(rng, ns):
    return (f"resource legacy 'Microsoft.Storage/storageAccounts@2023-01-01' = {{\n"
            f"  name: 'legacy{ns['SFX']}'\n"
            "  location: 'westeurope'\n  kind: 'StorageV2'\n"
            "  sku: { name: 'Standard_LRS' }\n  properties: {\n"
            "    allowBlobPublicAccess: false\n"
            "    minimumTlsVersion: 'TLS1_0'\n"
            "    supportsHttpsTrafficOnly: true\n  }\n}\n")
reg('bicep', 'bicep_storage_weak_tls', bicep_file(_bicep_storage_weak_tls),
    concepts=['weak-tls'], desc='Bicep storage allowing TLS 1.0', cloud='azure')

def _bicep_nsg_open(rng, ns):
    return (f"resource web 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {{\n"
            f"  name: 'web-{ns['SFX']}'\n"
            "  location: 'westeurope'\n  properties: {\n"
            "    securityRules: [\n      {\n        name: 'allow-ssh'\n"
            "        properties: {\n          priority: 100\n"
            "          direction: 'Inbound'\n          access: 'Allow'\n"
            "          protocol: 'Tcp'\n          sourcePortRange: '*'\n"
            "          destinationPortRange: '22'\n"
            "          sourceAddressPrefix: '*'\n"
            "          destinationAddressPrefix: '*'\n"
            "        }\n      }\n    ]\n  }\n}\n")
reg('bicep', 'bicep_nsg_open', bicep_file(_bicep_nsg_open),
    concepts=['nsg-open'], desc='Bicep NSG with SSH open to the world', cloud='azure')

def _bicep_keyvault_nopurge(rng, ns):
    return (f"resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {{\n"
            f"  name: 'kv-{ns['SFX']}'\n"
            "  location: 'westeurope'\n  properties: {\n"
            "    sku: { family: 'A', name: 'standard' }\n"
            "    tenantId: '00000000-0000-0000-0000-000000000000'\n"
            "    enablePurgeProtection: false\n"
            "    enableSoftDelete: true\n    accessPolicies: []\n  }\n}\n")
reg('bicep', 'bicep_keyvault_nopurge', bicep_file(_bicep_keyvault_nopurge),
    concepts=['keyvault-no-purge'], desc='Bicep Key Vault without purge protection',
    cloud='azure')

def _bicep_secure(rng, ns):
    return (f"resource data 'Microsoft.Storage/storageAccounts@2023-01-01' = {{\n"
            f"  name: 'data{ns['SFX']}'\n"
            "  location: 'westeurope'\n  kind: 'StorageV2'\n"
            "  sku: { name: 'Standard_LRS' }\n  properties: {\n"
            "    allowBlobPublicAccess: false\n"
            "    minimumTlsVersion: 'TLS1_2'\n"
            "    supportsHttpsTrafficOnly: true\n  }\n}\n"
            f"resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {{\n"
            f"  name: 'kv-{ns['SFX']}'\n"
            "  location: 'westeurope'\n  properties: {\n"
            "    sku: { family: 'A', name: 'standard' }\n"
            "    tenantId: '00000000-0000-0000-0000-000000000000'\n"
            "    enablePurgeProtection: true\n"
            "    enableSoftDelete: true\n    accessPolicies: []\n  }\n}\n")
reg('bicep', 'bicep_secure', bicep_file(_bicep_secure), secure=True,
    desc='Bicep hardened storage + key vault', cloud='azure')

# ---------------------------------------------------------------- PULUMI (YAML)
# Two layouts: template:-nested and top-level resources.
def pulumi_file(body, layout):
    def gen(rng, ns):
        content = body(rng, ns)
        return {'Pulumi.yaml': content}
    return gen

def _pu_resources_aws(rng, ns, vuln):
    acl = 'public-read' if vuln else 'private'
    return (f'    siteBucket:\n      type: aws:s3:Bucket\n'
            f'      properties:\n        bucket: site-{ns["SFX"]}\n'
            f'        acl: {acl}\n')

def _pu_sg_aws(rng, ns, vuln):
    cidr = '0.0.0.0/0' if vuln else ns['OFFICE']
    return (f'    bastionSg:\n      type: aws:ec2:SecurityGroup\n'
            f'      properties:\n        name: bastion-{ns["SFX"]}\n'
            f'        description: bastion access\n'
            f'        ingress:\n'
            f'          - protocol: tcp\n            fromPort: 22\n'
            f'            toPort: 22\n            cidrBlocks: ["{cidr}"]\n'
            f'        egress:\n'
            f'          - protocol: "-1"\n            fromPort: 0\n'
            f'            toPort: 0\n            cidrBlocks: ["0.0.0.0/0"]\n')

def _pu_ec2_aws(rng, ns, vuln):
    imds = ('        metadataOptions:\n'
            '          httpTokens: required\n'
            '          httpEndpoint: enabled\n') if not vuln else ''
    return (f'    webServer:\n      type: aws:ec2:Instance\n'
            f'      properties:\n        ami: ami-0c55b159cbfafe1f0\n'
            f'        instanceType: t3.micro\n'
            f'{imds}'
            f'        tags:\n          Name: web-{ns["SFX"]}\n')

def _pu_storage_az(rng, ns, vuln):
    blob = 'true' if vuln else 'false'
    return (f'    dataAccount:\n      type: azure-native:storage:StorageAccount\n'
            f'      properties:\n        accountName: data{ns["SFX"]}\n'
            f'        resourceGroupName: rg-data\n'
            f'        location: westeurope\n'
            f'        kind: StorageV2\n'
            f'        sku:\n          name: Standard_LRS\n'
            f'        allowBlobPublicAccess: {blob}\n'
            f'        minimumTlsVersion: TLS1_2\n'
            f'        supportsHttpsTrafficOnly: true\n')

def _pu_keyvault_az(rng, ns, vuln):
    purge = 'false' if vuln else 'true'
    return (f'    mainVault:\n      type: azure-native:keyvault:Vault\n'
            f'      properties:\n        vaultName: kv-{ns["SFX"]}\n'
            f'        resourceGroupName: rg-kv\n'
            f'        location: westeurope\n'
            f'        properties:\n'
            f'          sku:\n            family: A\n            name: standard\n'
            f'          tenantId: 00000000-0000-0000-0000-000000000000\n'
            f'          enablePurgeProtection: {purge}\n'
            f'          enableSoftDelete: true\n')

def _pu_nsg_az(rng, ns, vuln):
    src = '*' if vuln else ns['OFFICE']
    return (f'    webNsg:\n      type: azure-native:network:NetworkSecurityGroup\n'
            f'      properties:\n        networkSecurityGroupName: web-{ns["SFX"]}\n'
            f'        resourceGroupName: rg-web\n'
            f'        location: westeurope\n'
            f'        securityRules:\n'
            f'          - name: allow-ssh\n'
            f'            properties:\n'
            f'              priority: 100\n'
            f'              direction: Inbound\n'
            f'              access: Allow\n'
            f'              protocol: Tcp\n'
            f'              sourcePortRange: "*"\n'
            f'              destinationPortRange: "22"\n'
            f'              sourceAddressPrefix: "{src}"\n'
            f'              destinationAddressPrefix: "*"\n')

def _pulumi_doc(ns, res_block, layout):
    head = (f'name: {ns["N"]}-stack\n'
            f'runtime: yaml\n'
            f'description: Pulumi stack ({layout} layout)\n')
    if layout == 'template':
        return head + 'template:\n  resources:\n' + res_block
    return head + 'resources:\n' + res_block

PU_VULN_SETS = [
    ('pu_aws_s3_public', _pu_resources_aws, ['s3-public-acl'], 'aws',
     'Pulumi stack with public S3 bucket'),
    ('pu_aws_sg_open', _pu_sg_aws, ['sg-open-ssh'], 'aws',
     'Pulumi stack with SSH open to the internet'),
    ('pu_aws_ec2_imds', _pu_ec2_aws, ['imdsv1'], 'aws',
     'Pulumi EC2 with IMDSv1 enabled'),
    ('pu_az_storage_public', _pu_storage_az, ['storage-public-azure'], 'azure',
     'Pulumi stack with public blob access'),
    ('pu_az_keyvault_nopurge', _pu_keyvault_az, ['keyvault-no-purge'], 'azure',
     'Pulumi Key Vault without purge protection'),
    ('pu_az_nsg_open', _pu_nsg_az, ['nsg-open'], 'azure',
     'Pulumi NSG with SSH open to the world'),
]
PU_SECURE_SETS = [
    ('pu_aws_s3_secure', _pu_resources_aws, 'aws', 'Pulumi stack with private S3 bucket'),
    ('pu_aws_sg_secure', _pu_sg_aws, 'aws', 'Pulumi stack with restricted SSH'),
    ('pu_az_storage_secure', _pu_storage_az, 'azure', 'Pulumi hardened storage account'),
    ('pu_az_keyvault_secure', _pu_keyvault_az, 'azure', 'Pulumi hardened key vault'),
]

for _name, _fn, _concepts, _cloud, _desc in PU_VULN_SETS:
    for _layout in ('template', 'toplevel'):
        def _mk(rng, ns, _fn=_fn, _layout=_layout, _vuln=True):
            return _pulumi_doc(ns, _fn(rng, ns, _vuln), _layout)
        reg('pulumi', f'{_name}_{_layout}', pulumi_file(_mk, _layout),
            concepts=_concepts, desc=f'{_desc} [{_layout} layout]', cloud=_cloud)
for _name, _fn, _cloud, _desc in PU_SECURE_SETS:
    for _layout in ('template', 'toplevel'):
        def _mk(rng, ns, _fn=_fn, _layout=_layout):
            return _pulumi_doc(ns, _fn(rng, ns, False), _layout)
        reg('pulumi', f'{_name}_{_layout}', pulumi_file(_mk, _layout),
            secure=True, desc=f'{_desc} [{_layout} layout]', cloud=_cloud)

# ---------------------------------------------------------------- DOCKERFILE
def docker_file(body):
    return lambda rng, ns: {'Dockerfile': body(rng, ns)}

def _dk_root(rng, ns):
    return ('FROM ubuntu:22.04\n'
            'RUN apt-get update && apt-get install -y python3 python3-pip\n'
            'WORKDIR /app\nCOPY requirements.txt .\n'
            'RUN pip3 install -r requirements.txt\nCOPY . .\n'
            'EXPOSE 8000\nCMD ["python3", "app.py"]\n')
reg('dockerfile', 'dk_root', docker_file(_dk_root),
    concepts=['docker-root'], desc='Python Dockerfile running as root', cloud='none')

def _dk_secret(rng, ns):
    return ('FROM python:3.11-slim\n'
            'WORKDIR /app\n'
            'ENV DATABASE_URL="postgres://admin:Sup3rSecret!-prod@db:5432/app"\n'
            'ENV STRIPE_KEY="sk_live_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c"\n'
            'COPY . .\nRUN useradd -m app && chown -R app /app\nUSER app\n'
            'CMD ["python", "app.py"]\n')
reg('dockerfile', 'dk_secret', docker_file(_dk_secret),
    concepts=['docker-secret'], desc='Dockerfile with secrets baked into ENV',
    cloud='none')

def _dk_latest(rng, ns):
    return ('FROM node:latest\n'
            'WORKDIR /srv\nCOPY package*.json ./\n'
            'RUN npm ci --omit=dev\nCOPY . .\n'
            'RUN useradd -m svc && chown -R svc /srv\nUSER svc\n'
            'HEALTHCHECK --interval=30s CMD node healthcheck.js\n'
            'CMD ["node", "server.js"]\n')
reg('dockerfile', 'dk_latest', docker_file(_dk_latest),
    concepts=['docker-latest'], desc='Node Dockerfile pinned to latest tag', cloud='none')

def _dk_nohealth(rng, ns):
    return ('FROM python:3.11.9-slim-bookworm\n'
            'WORKDIR /app\nCOPY . .\n'
            'RUN useradd -m app && chown -R app /app\nUSER app\n'
            'EXPOSE 8000\nCMD ["python", "app.py"]\n')
reg('dockerfile', 'dk_nohealth', docker_file(_dk_nohealth),
    concepts=['docker-no-healthcheck'], desc='Dockerfile without HEALTHCHECK',
    cloud='none')

def _dk_add_remote(rng, ns):
    return ('FROM python:3.11-slim\n'
            'WORKDIR /app\n'
            'ADD https://example.com/releases/agent-2.4.1.tar.gz /tmp/\n'
            'RUN tar -xzf /tmp/agent-2.4.1.tar.gz -C /opt && rm /tmp/agent-2.4.1.tar.gz\n'
            'COPY . .\nRUN useradd -m app && chown -R app /app\nUSER app\n'
            'HEALTHCHECK CMD curl -f http://localhost:8000/health || exit 1\n'
            'CMD ["python", "app.py"]\n')
reg('dockerfile', 'dk_add_remote', docker_file(_dk_add_remote),
    concepts=['docker-add-remote'], desc='Dockerfile fetching remote tarball via ADD',
    cloud='none')

def _dk_build_tools(rng, ns):
    return ('FROM golang:1.22-bookworm AS build\n'
            'WORKDIR /src\nCOPY . .\nRUN go build -o /app/server .\n'
            'FROM debian:bookworm-slim\n'
            'RUN apt-get update && apt-get install -y gcc git curl strace vim\n'
            'COPY --from=build /app/server /app/server\n'
            'RUN useradd -m app\nUSER app\n'
            'HEALTHCHECK CMD /app/server -health\n'
            'CMD ["/app/server"]\n')
reg('dockerfile', 'dk_build_tools', docker_file(_dk_build_tools),
    concepts=['docker-build-tools'], desc='Final image reinstalls build/debug tools',
    cloud='none')

def _dk_curlpipe(rng, ns):
    return ('FROM ubuntu:22.04\n'
            'RUN apt-get update && apt-get install -y curl\n'
            'RUN curl -fsSL https://example.com/install.sh | bash\n'
            'WORKDIR /app\nCOPY . .\nRUN useradd -m app && chown -R app /app\nUSER app\n'
            'HEALTHCHECK CMD true\nCMD ["./run.sh"]\n')
reg('dockerfile', 'dk_curlpipe', docker_file(_dk_curlpipe),
    concepts=['curl-pipe-shell'], desc='Dockerfile piping curl to shell', cloud='none')

def _dk_secure(rng, ns):
    return ('FROM python:3.11.9-slim-bookworm\n'
            'WORKDIR /app\nCOPY requirements.txt .\n'
            'RUN pip install --no-cache-dir -r requirements.txt\n'
            'COPY --chown=app:app . .\n'
            'RUN useradd -m app\nUSER app\n'
            'HEALTHCHECK --interval=30s CMD python -c "import urllib.request; urllib.request.urlopen(\'http://localhost:8000/health\')"\n'
            'EXPOSE 8000\nCMD ["python", "app.py"]\n')
reg('dockerfile', 'dk_secure', docker_file(_dk_secure), secure=True,
    desc='Hardened Python Dockerfile', cloud='none')

def _dk_secure_go(rng, ns):
    return ('FROM golang:1.22-bookworm AS build\n'
            'WORKDIR /src\nCOPY . .\nRUN CGO_ENABLED=0 go build -o /app/server .\n'
            'FROM gcr.io/distroless/static-debian12:nonroot\n'
            'COPY --from=build /app/server /app/server\n'
            'USER nonroot\nCMD ["/app/server"]\n')
reg('dockerfile', 'dk_secure_go', docker_file(_dk_secure_go), secure=True,
    desc='Distroless nonroot Go Dockerfile', cloud='none')

# ---------------------------------------------------------------- COMPOSE
def compose_file(body):
    return lambda rng, ns: {'docker-compose.yml': body(rng, ns)}

def _co_sock(rng, ns):
    return ('services:\n'
            '  agent:\n    image: registry.example.com/agent:2.4.1\n'
            '    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n'
            '    restart: unless-stopped\n')
reg('compose', 'co_sock', compose_file(_co_sock),
    concepts=['compose-docker-sock'], desc='Compose mounting the Docker socket',
    cloud='none')

def _co_privileged(rng, ns):
    return ('services:\n'
            '  monitor:\n    image: registry.example.com/monitor:1.9.0\n'
            '    privileged: true\n'
            '    pid: host\n'
            '    volumes:\n      - /:/host:ro\n')
reg('compose', 'co_privileged', compose_file(_co_privileged),
    concepts=['compose-privileged'], desc='Compose service sharing host namespaces',
    cloud='none')

def _co_secret_env(rng, ns):
    return ('services:\n'
            '  api:\n    image: registry.example.com/api:3.2.0\n'
            '    environment:\n'
            '      DATABASE_URL: postgres://admin:Sup3rSecret!-prod@db:5432/app\n'
            '      AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETKEY\n'
            '  db:\n    image: postgres:15.4\n'
            '    environment:\n'
            '      POSTGRES_PASSWORD: Sup3rSecret!-prod\n')
reg('compose', 'co_secret_env', compose_file(_co_secret_env),
    concepts=['docker-secret'], desc='Compose with secrets in environment',
    cloud='none')

def _co_latest(rng, ns):
    return ('services:\n'
            '  web:\n    image: registry.example.com/web:latest\n'
            '    ports: ["8080:8080"]\n'
            '  worker:\n    image: registry.example.com/worker:latest\n')
reg('compose', 'co_latest', compose_file(_co_latest),
    concepts=['docker-latest'], desc='Compose using latest image tags', cloud='none')

def _co_secure(rng, ns):
    return ('services:\n'
            '  api:\n    image: registry.example.com/api:3.2.0\n'
            '    user: "10001:10001"\n'
            '    read_only: true\n'
            '    cap_drop: [ALL]\n'
            '    secrets: [db_password]\n'
            '  db:\n    image: postgres:15.4\n'
            '    secrets: [db_password]\n'
            'secrets:\n  db_password:\n    file: ./secrets/db_password.txt\n')
reg('compose', 'co_secure', compose_file(_co_secure), secure=True,
    desc='Compose with read-only fs, dropped caps and file secrets', cloud='none')

# ---------------------------------------------------------------- KUBERNETES
def k8s_file(body):
    return lambda rng, ns: {'deployment.yaml': body(rng, ns)}

def _k8s_hdr(kind, name):
    return (f'apiVersion: apps/v1\nkind: {kind}\nmetadata:\n'
            f'  name: {name}\n  labels:\n    app: {name}\n')

def _k8s_privileged(rng, ns):
    n = f'api-{ns["SFX"]}'
    return (_k8s_hdr('Deployment', n)
            + 'spec:\n  replicas: 2\n  selector:\n    matchLabels:\n'
            f'      app: {n}\n  template:\n    metadata:\n      labels:\n'
            f'        app: {n}\n    spec:\n      containers:\n'
            '        - name: api\n'
            '          image: registry.example.com/api:3.2.0\n'
            '          securityContext:\n'
            '            privileged: true\n'
            '            capabilities:\n              add: [SYS_ADMIN, NET_ADMIN]\n')
reg('kubernetes', 'k8s_privileged', k8s_file(_k8s_privileged),
    concepts=['k8s-privileged'], desc='Deployment with privileged container',
    cloud='none')

def _k8s_host(rng, ns):
    n = f'monitor-{ns["SFX"]}'
    return (_k8s_hdr('DaemonSet', n).replace('apps/v1', 'apps/v1')
            + 'spec:\n  selector:\n    matchLabels:\n'
            f'      app: {n}\n  template:\n    metadata:\n      labels:\n'
            f'        app: {n}\n    spec:\n      hostNetwork: true\n'
            '      hostPID: true\n      containers:\n'
            '        - name: monitor\n'
            '          image: registry.example.com/monitor:1.9.0\n'
            '          volumeMounts:\n'
            '            - name: hostroot\n              mountPath: /host\n'
            '      volumes:\n'
            '        - name: hostroot\n          hostPath:\n            path: /\n')
reg('kubernetes', 'k8s_host', k8s_file(_k8s_host),
    concepts=['k8s-host'], desc='DaemonSet sharing host network, PID and root fs',
    cloud='none')

def _k8s_no_limits(rng, ns):
    n = f'web-{ns["SFX"]}'
    return (_k8s_hdr('Deployment', n)
            + 'spec:\n  replicas: 3\n  selector:\n    matchLabels:\n'
            f'      app: {n}\n  template:\n    metadata:\n      labels:\n'
            f'        app: {n}\n    spec:\n'
            '      securityContext:\n'
            '        runAsNonRoot: true\n'
            '        runAsUser: 10001\n'
            '      containers:\n'
            '        - name: web\n'
            '          image: registry.example.com/web:2.1.0\n'
            '          ports: [{containerPort: 8080}]\n'
            '          livenessProbe:\n'
            '            httpGet: {path: /health, port: 8080}\n'
            '            initialDelaySeconds: 10\n')
reg('kubernetes', 'k8s_no_limits', k8s_file(_k8s_no_limits),
    concepts=['k8s-no-limits'], desc='Deployment without resource limits', cloud='none')

def _k8s_no_probe(rng, ns):
    n = f'worker-{ns["SFX"]}'
    return (_k8s_hdr('Deployment', n)
            + 'spec:\n  replicas: 2\n  selector:\n    matchLabels:\n'
            f'      app: {n}\n  template:\n    metadata:\n      labels:\n'
            f'        app: {n}\n    spec:\n'
            '      securityContext:\n'
            '        runAsNonRoot: true\n'
            '        runAsUser: 10001\n'
            '      containers:\n'
            '        - name: worker\n'
            '          image: registry.example.com/worker:1.4.0\n'
            '          resources:\n'
            '            limits: {cpu: "500m", memory: 256Mi}\n'
            '            requests: {cpu: "250m", memory: 128Mi}\n')
reg('kubernetes', 'k8s_no_probe', k8s_file(_k8s_no_probe),
    concepts=['k8s-no-probe'], desc='Deployment without liveness/readiness probes',
    cloud='none')

def _k8s_no_secctx(rng, ns):
    n = f'api-{ns["SFX"]}'
    return (_k8s_hdr('Deployment', n)
            + 'spec:\n  replicas: 2\n  selector:\n    matchLabels:\n'
            f'      app: {n}\n  template:\n    metadata:\n      labels:\n'
            f'        app: {n}\n    spec:\n      containers:\n'
            '        - name: api\n'
            '          image: registry.example.com/api:3.2.0\n'
            '          resources:\n'
            '            limits: {cpu: "500m", memory: 256Mi}\n'
            '          livenessProbe:\n'
            '            httpGet: {path: /health, port: 8080}\n')
reg('kubernetes', 'k8s_no_secctx', k8s_file(_k8s_no_secctx),
    concepts=['k8s-no-security-context'], desc='Deployment with no securityContext',
    cloud='none')

def _k8s_secret_env(rng, ns):
    n = f'api-{ns["SFX"]}'
    return (_k8s_hdr('Deployment', n)
            + 'spec:\n  replicas: 2\n  selector:\n    matchLabels:\n'
            f'      app: {n}\n  template:\n    metadata:\n      labels:\n'
            f'        app: {n}\n    spec:\n'
            '      securityContext:\n'
            '        runAsNonRoot: true\n'
            '      containers:\n'
            '        - name: api\n'
            '          image: registry.example.com/api:3.2.0\n'
            '          env:\n'
            '            - name: DB_PASSWORD\n'
            '              value: Sup3rSecret!-prod-2024\n'
            '            - name: API_TOKEN\n'
            '              value: tok_live_9f8a7b6c5d4e3f2a1b0c\n')
reg('kubernetes', 'k8s_secret_env', k8s_file(_k8s_secret_env),
    concepts=['k8s-secret-env'], desc='Deployment with secrets in env vars',
    cloud='none')

def _k8s_rbac_broad(rng, ns):
    n = f'deployer-{ns["SFX"]}'
    return ('apiVersion: rbac.authorization.k8s.io/v1\n'
            'kind: ClusterRoleBinding\nmetadata:\n'
            f'  name: {n}\n'
            'subjects:\n  - kind: ServiceAccount\n'
            f'    name: {n}\n    namespace: default\n'
            'roleRef:\n  kind: ClusterRole\n'
            '  name: cluster-admin\n  apiGroup: rbac.authorization.k8s.io\n')
reg('kubernetes', 'k8s_rbac_broad', k8s_file(_k8s_rbac_broad),
    concepts=['k8s-rbac-broad'], desc='ClusterRoleBinding granting cluster-admin',
    cloud='none')

def _k8s_secure(rng, ns):
    n = f'api-{ns["SFX"]}'
    return (_k8s_hdr('Deployment', n)
            + 'spec:\n  replicas: 3\n  selector:\n    matchLabels:\n'
            f'      app: {n}\n  template:\n    metadata:\n      labels:\n'
            f'        app: {n}\n    spec:\n'
            '      securityContext:\n'
            '        runAsNonRoot: true\n'
            '        runAsUser: 10001\n'
            '        seccompProfile: {type: RuntimeDefault}\n'
            '      containers:\n'
            '        - name: api\n'
            '          image: registry.example.com/api:3.2.0\n'
            '          securityContext:\n'
            '            allowPrivilegeEscalation: false\n'
            '            readOnlyRootFilesystem: true\n'
            '            capabilities: {drop: [ALL]}\n'
            '          resources:\n'
            '            limits: {cpu: "500m", memory: 256Mi}\n'
            '            requests: {cpu: "250m", memory: 128Mi}\n'
            '          livenessProbe:\n'
            '            httpGet: {path: /health, port: 8080}\n'
            '            initialDelaySeconds: 10\n'
            '          readinessProbe:\n'
            '            httpGet: {path: /ready, port: 8080}\n')
reg('kubernetes', 'k8s_secure', k8s_file(_k8s_secure), secure=True,
    desc='Hardened Deployment', cloud='none')

def _k8s_networkpolicy_absent(rng, ns):
    n = f'web-{ns["SFX"]}'
    return (_k8s_hdr('Deployment', n)
            + 'spec:\n  replicas: 2\n  selector:\n    matchLabels:\n'
            f'      app: {n}\n  template:\n    metadata:\n      labels:\n'
            f'        app: {n}\n    spec:\n'
            '      securityContext:\n'
            '        runAsNonRoot: true\n'
            '      containers:\n'
            '        - name: web\n'
            '          image: registry.example.com/web:2.1.0\n'
            '          resources:\n'
            '            limits: {cpu: "250m", memory: 128Mi}\n'
            '          livenessProbe:\n'
            '            httpGet: {path: /health, port: 8080}\n',
            )
# networkpolicy absence handled at project level: the deployment is otherwise
# locked down but exposes a public LoadBalancer with no NetworkPolicy in ns.
def _k8s_np_files(rng, ns):
    n = f'web-{ns["SFX"]}'
    dep = (_k8s_hdr('Deployment', n)
           + 'spec:\n  replicas: 2\n  selector:\n    matchLabels:\n'
           f'      app: {n}\n  template:\n    metadata:\n      labels:\n'
           f'        app: {n}\n    spec:\n'
           '      securityContext:\n'
           '        runAsNonRoot: true\n'
           '      containers:\n'
           '        - name: web\n'
           '          image: registry.example.com/web:2.1.0\n'
           '          resources:\n'
           '            limits: {cpu: "250m", memory: 128Mi}\n'
           '          livenessProbe:\n'
           '            httpGet: {path: /health, port: 8080}\n')
    svc = (f'apiVersion: v1\nkind: Service\nmetadata:\n  name: {n}\n'
           f'spec:\n  type: LoadBalancer\n  selector:\n    app: {n}\n'
           '  ports: [{port: 80, targetPort: 8080}]\n')
    return {'deployment.yaml': dep, 'service.yaml': svc}
reg('kubernetes', 'k8s_no_networkpolicy', _k8s_np_files,
    concepts=['k8s-no-networkpolicy'],
    desc='Public LoadBalancer service with no NetworkPolicy in namespace',
    cloud='none')

# ---------------------------------------------------------------- DRIVER
FORMATS = ['terraform', 'cloudformation', 'arm', 'bicep', 'pulumi',
           'dockerfile', 'compose', 'kubernetes']
FMT_COUNTS = {'terraform': 40, 'cloudformation': 30, 'arm': 15, 'bicep': 15,
              'pulumi': 20, 'dockerfile': 30, 'compose': 25, 'kubernetes': 35}
FMT_FILES = {'terraform': 'main.tf', 'cloudformation': 'template.yaml',
             'arm': 'azuredeploy.json', 'bicep': 'main.bicep',
             'pulumi': 'Pulumi.yaml', 'dockerfile': 'Dockerfile',
             'compose': 'docker-compose.yml', 'kubernetes': 'deployment.yaml'}
FMT_CLOUD = {'terraform': 'aws', 'cloudformation': 'aws', 'arm': 'azure',
             'bicep': 'azure', 'pulumi': 'aws', 'dockerfile': 'none',
             'compose': 'none', 'kubernetes': 'none'}

SINGLE_FILE = {'dockerfile', 'compose'}
SUBTLE = {'tf_iam_trust_broad', 'tf_kms_no_rotation', 'tf_rds_weakpw',
          'tf_rds_nobackup', 'tf_vm_ipforward', 'tf_az_storage_weak_tls',
          'tf_eks_public', 'cfn_kms_no_rotation', 'cfn_eks_public',
          'cfn_lambda_url_public', 'arm_storage_weak_tls',
          'bicep_storage_weak_tls', 'k8s_no_secctx', 'k8s_no_networkpolicy',
          'dk_add_remote', 'co_latest', 'tf_lambda_url_public',
          'tf_secret_var', 'cfn_secret_param'}
NOPARAM_CFN = {'cfn_secret_param'}  # not merge-safe in multi-block projects

def pick_blocks(fmt, profile, difficulty, rng, layout=None):
    pool = BLOCKS[fmt]
    if layout:  # pulumi
        pool = [b for b in pool if b['name'].endswith('_' + layout)]
    vuln = [b for b in pool if not b['secure']]
    sec = [b for b in pool if b['secure']]
    if profile == 'mixed' and fmt in SINGLE_FILE:
        mixed_pool = [b for b in pool
                      if b['name'].startswith(('dk_mixed_', 'co_mixed_'))]
        return rng.sample(mixed_pool, 1)
    if profile == 'vulnerable':
        n = {'easy': 1, 'medium': 2, 'hard': 2}[difficulty]
        cand = vuln
        if difficulty == 'hard':
            subtle = [b for b in cand if b['name'] in SUBTLE]
            if subtle:
                cand = subtle
        chosen = rng.sample(cand, min(n, len(cand)))
    elif profile == 'secure':
        n = 1 if fmt in SINGLE_FILE else 2
        chosen = rng.sample(sec, min(n, len(sec)))
    else:  # mixed
        v = rng.sample(vuln, 1)
        ns_ = min(2 if difficulty == 'hard' else 1, len(sec))
        s = rng.sample(sec, ns_)
        if fmt == 'cloudformation':
            v = [b for b in v if b['name'] not in NOPARAM_CFN] or v
            s = [b for b in s if b['name'] not in NOPARAM_CFN] or s
        chosen = v + s
        rng.shuffle(chosen)
    # dedupe by name (e.g. sampled same block twice is impossible via sample)
    seen, out = set(), []
    for b in chosen:
        if b['name'] not in seen:
            seen.add(b['name'])
            out.append(b)
    return out

def merge_files(fmt, blocks, rng, ns):
    """Assemble {relpath: content} for a project."""
    if len(blocks) == 1 and fmt not in ('arm',):
        return blocks[0]['files'](rng, ns)
    if fmt == 'terraform' or fmt == 'bicep':
        fn = FMT_FILES[fmt]
        body = '\n'.join(blocks and [b['files'](rng, ns)[fn] for b in blocks])
        return {fn: body}
    if fmt == 'cloudformation':
        parts = []
        for i, b in enumerate(blocks):
            txt = b['files'](rng, ns)['template.yaml']
            if i > 0:
                lines = txt.split('\n')
                txt = '\n'.join(lines[3:])  # drop AWSTemplateFormatVersion/Description/Resources:
            parts.append(txt)
        return {'template.yaml': '\n'.join(parts)}
    if fmt == 'arm':
        merged = None
        for b in blocks:
            d = json.loads(b['files'](rng, ns)['azuredeploy.json'])
            if merged is None:
                merged = d
            else:
                merged['resources'].extend(d['resources'])
        return {'azuredeploy.json': json.dumps(merged, indent=2) + '\n'}
    if fmt == 'pulumi':
        head = None
        res_lines = []
        parent = None
        for b in blocks:
            txt = b['files'](rng, ns)['Pulumi.yaml']
            lines = txt.split('\n')
            if head is None:
                head = '\n'.join(lines[:3])
                parent = 'template:' if lines[3].startswith('template:') else 'resources:'
            # resource lines: everything from the resources:/template: section
            idx = next(i for i, l in enumerate(lines) if l in ('template:', 'resources:'))
            ridx = idx + 2 if lines[idx + 1].strip() == 'resources:' else idx + 1
            res_lines.extend(lines[ridx:])
        body = head + '\n' + parent + '\n'
        if parent == 'template:':
            body += '  resources:\n'
        body += '\n'.join(res_lines)
        return {'Pulumi.yaml': body}
    if fmt == 'kubernetes':
        docs = []
        for b in blocks:
            for _fn, content in b['files'](rng, ns).items():
                docs.append(content)
        return {'deployment.yaml': '\n---\n'.join(docs)}
    # dockerfile / compose: single-file formats. NOTE (round-3 post-gen QA):
    # pick_blocks may return >1 block for these formats, but only blocks[0]
    # is written. The sealed injection plan was corrected to blocks_written.
    # Do not regenerate; fix pick_blocks to sample 1 for SINGLE_FILE instead.
    return blocks[0]['files'](rng, ns)

PROFILE_PLAN = {
    'terraform': ('vulnerable', 16, 'secure', 12, 'mixed', 12),
    'cloudformation': ('vulnerable', 12, 'secure', 9, 'mixed', 9),
    'arm': ('vulnerable', 6, 'secure', 4, 'mixed', 5),
    'bicep': ('vulnerable', 6, 'secure', 4, 'mixed', 5),
    'pulumi': ('vulnerable', 8, 'secure', 6, 'mixed', 6),
    'dockerfile': ('vulnerable', 14, 'secure', 10, 'mixed', 6),
    'compose': ('vulnerable', 11, 'secure', 8, 'mixed', 6),
    'kubernetes': ('vulnerable', 14, 'secure', 11, 'mixed', 10),
}

def difficulty_for(i, n):
    r = (i % 10)
    if r < 4:
        return 'easy'
    if r < 8:
        return 'medium'
    return 'hard'

def main():
    rng = random.Random(SEED)
    if os.path.exists(CORPUS):
        shutil.rmtree(CORPUS)
    os.makedirs(CORPUS)
    os.makedirs(SEALED, exist_ok=True)
    manifest = []
    plan = {}
    pid_n = 3001
    for fmt in FORMATS:
        n = FMT_COUNTS[fmt]
        profs = []
        spec = PROFILE_PLAN[fmt]
        for k in range(0, len(spec), 2):
            profs.extend([spec[k]] * spec[k + 1])
        assert len(profs) == n, (fmt, len(profs), n)
        rng.shuffle(profs)
        for i, profile in enumerate(profs):
            pid = f'r{pid_n}'
            pid_n += 1
            difficulty = difficulty_for(i, n)
            layout = None
            if fmt == 'pulumi':
                # force 10 template + 10 toplevel across the 20 projects
                layout = 'template' if i < 10 else 'toplevel'
            blocks = pick_blocks(fmt, profile, difficulty, rng, layout)
            ns = ns_of(pid, rng)
            ns['N'] = pid
            files = merge_files(fmt, blocks, rng, ns)
            pdir = os.path.join(CORPUS, pid)
            os.makedirs(pdir)
            for rel, content in files.items():
                with open(os.path.join(pdir, rel), 'w') as f:
                    f.write(content)
            concepts = sorted({c for b in blocks for c in b['concepts']})
            clouds = sorted({b['cloud'] for b in blocks})
            cloud = clouds[0] if len(clouds) == 1 else 'multi'
            desc = '; '.join(b['desc'] for b in blocks)
            if layout:
                desc += f' [pulumi {layout} layout]'
            manifest.append({'id': pid, 'format': fmt, 'cloud': cloud,
                             'difficulty': difficulty, 'profile': profile,
                             'description': desc})
            plan[pid] = {'blocks': [b['name'] for b in blocks],
                         'injected_concepts': concepts,
                         'layout': layout}
    manifest.sort(key=lambda e: e['id'])
    with open(os.path.join(CORPUS, 'MANIFEST.json'), 'w') as f:
        json.dump(manifest, f, indent=1)
    with open(os.path.join(SEALED, 'injection-plan.json'), 'w') as f:
        json.dump(plan, f, indent=1)
    with open(os.path.join(SEALED, 'README.txt'), 'w') as f:
        f.write('SEALED: injection plan. Do NOT open until labeling + '
                'adjudication are complete.\n')
    # summary
    from collections import Counter
    print('projects:', len(manifest))
    print('formats:', Counter(e['format'] for e in manifest))
    print('profiles:', Counter(e['profile'] for e in manifest))
    print('difficulty:', Counter(e['difficulty'] for e in manifest))
    print('pulumi layouts:', Counter(plan[e['id']]['layout'] for e in manifest
                                     if e['format'] == 'pulumi'))

# --- dedicated mixed-profile blocks for single-file formats ---
def _dk_mixed_nohealth(rng, ns):
    return ('FROM python:3.11.9-slim-bookworm\n'
            'WORKDIR /app\nCOPY requirements.txt .\n'
            'RUN pip install --no-cache-dir -r requirements.txt\n'
            'COPY --chown=app:app . .\n'
            'RUN useradd -m app\nUSER app\n'
            'EXPOSE 8000\nCMD ["python", "app.py"]\n')
reg('dockerfile', 'dk_mixed_nohealth', docker_file(_dk_mixed_nohealth),
    concepts=['docker-no-healthcheck'],
    desc='Mostly hardened Dockerfile but no HEALTHCHECK', cloud='none')

def _dk_mixed_tools(rng, ns):
    return ('FROM python:3.11.9-slim-bookworm\n'
            'RUN apt-get update && apt-get install -y curl git strace\n'
            'WORKDIR /app\nCOPY --chown=app:app . .\n'
            'RUN useradd -m app\nUSER app\n'
            'HEALTHCHECK --interval=30s CMD python -c "print(1)"\n'
            'CMD ["python", "app.py"]\n')
reg('dockerfile', 'dk_mixed_tools', docker_file(_dk_mixed_tools),
    concepts=['docker-build-tools'],
    desc='Non-root Dockerfile that still ships debug tooling', cloud='none')

def _co_mixed_latest(rng, ns):
    return ('services:\n'
            '  api:\n    image: registry.example.com/api:3.2.0\n'
            '    user: "10001:10001"\n'
            '    read_only: true\n'
            '    cap_drop: [ALL]\n'
            '  worker:\n    image: registry.example.com/worker:latest\n'
            '    user: "10001:10001"\n')
reg('compose', 'co_mixed_latest', compose_file(_co_mixed_latest),
    concepts=['docker-latest'],
    desc='Compose with hardened api but floating latest worker tag', cloud='none')

def _co_mixed_secret(rng, ns):
    return ('services:\n'
            '  api:\n    image: registry.example.com/api:3.2.0\n'
            '    user: "10001:10001"\n'
            '    read_only: true\n'
            '    environment:\n'
            '      API_TOKEN: tok_live_9f8a7b6c5d4e3f2a1b0c\n')
reg('compose', 'co_mixed_secret', compose_file(_co_mixed_secret),
    concepts=['docker-secret'],
    desc='Hardened compose service with a token in environment', cloud='none')

if __name__ == "__main__":
    main()
