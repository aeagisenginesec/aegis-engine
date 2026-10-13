#!/usr/bin/env python3
"""Build MANIFEST.json and MANIFEST-c-backup.json for the c-group corpus (c001-c070).

Appends c-entries to the existing shared MANIFEST.json via read-modify-write
(a sibling worker owns the k-group entries in the same file).
"""
import json
import os
from collections import Counter

BASE = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval/corpus")
MANIFEST = os.path.join(BASE, "MANIFEST.json")
BACKUP = os.path.join(BASE, "MANIFEST-c-backup.json")

ENTRIES = [
    # --- CloudFormation YAML (c001-c020) ---
    {"id": "c001", "format": "cloudformation", "cloud": "aws", "difficulty": "easy", "profile": "vulnerable",
     "description": "S3 static website bucket with public-read ACL and a public bucket policy; no encryption, versioning, logging or public-access block (YAML)."},
    {"id": "c002", "format": "cloudformation", "cloud": "aws", "difficulty": "easy", "profile": "secure",
     "description": "Data-lake raw bucket with SSE-KMS, versioning, full public-access block, lifecycle expiry and deny-unencrypted/TLS-only bucket policy (YAML)."},
    {"id": "c003", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "vulnerable",
     "description": "CI deploy role with AdministratorAccess managed policy plus an inline wildcard policy, and an over-broad account-root trust policy (YAML)."},
    {"id": "c004", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "secure",
     "description": "Least-privilege Lambda execution role scoped to one S3 prefix with TLS-only condition, source-account trust condition, permissions boundary and a 90-day log group (YAML)."},
    {"id": "c005", "format": "cloudformation", "cloud": "aws", "difficulty": "easy", "profile": "vulnerable",
     "description": "Dev EC2 jump box with SSH and RDP open to 0.0.0.0/0 and an unencrypted root volume (YAML)."},
    {"id": "c006", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "mixed",
     "description": "Bastion host with office-only SSH and encrypted EBS, but IMDSv1 still allowed via HttpTokens optional (YAML)."},
    {"id": "c007", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "vulnerable",
     "description": "MySQL RDS instance that is publicly accessible, unencrypted, with no backups and a security group open on 3306 to the internet (YAML)."},
    {"id": "c008", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "secure",
     "description": "Production Postgres: SSE-KMS, Multi-AZ, private subnets, Secrets Manager master password, deletion protection and 7-day backups (YAML)."},
    {"id": "c009", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "vulnerable",
     "description": "Webhook Lambda with a wildcard IAM role and database/API credentials in plaintext environment variables (YAML)."},
    {"id": "c010", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "secure",
     "description": "Invoice Lambda with KMS-encrypted environment, scoped role, active X-Ray tracing, DLQ and reserved concurrency (YAML)."},
    {"id": "c011", "format": "cloudformation", "cloud": "aws", "difficulty": "hard", "profile": "mixed",
     "description": "Docs site on S3+CloudFront with OAC and a locked-down origin bucket, but the distribution allows plain HTTP and has no WAF; uses Mappings and Conditions (YAML)."},
    {"id": "c012", "format": "cloudformation", "cloud": "aws", "difficulty": "hard", "profile": "mixed",
     "description": "Public-facing VPC with parameters and per-environment CIDR mappings; the public NACL allows all inbound traffic (YAML)."},
    {"id": "c013", "format": "cloudformation", "cloud": "aws", "difficulty": "easy", "profile": "vulnerable",
     "description": "Central S3 access-log bucket with no encryption and no versioning, plus a log-delivery bucket policy (YAML)."},
    {"id": "c014", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "vulnerable",
     "description": "On-call IAM user with AdministratorAccess, console login, an active access key and no MFA (YAML)."},
    {"id": "c015", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "secure",
     "description": "Multi-region CloudTrail with log file validation, KMS encryption, TLS-only encrypted bucket and CloudWatch Logs delivery (YAML)."},
    {"id": "c016", "format": "cloudformation", "cloud": "aws", "difficulty": "hard", "profile": "mixed",
     "description": "Web tier on ALB+ASG: instances hardened with encrypted EBS and IMDSv2, but the ALB listener is HTTP-only (YAML)."},
    {"id": "c017", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "vulnerable",
     "description": "Aurora MySQL cluster with a non-NoEcho password parameter, no storage encryption, minimal backups and a public, internet-open instance (YAML)."},
    {"id": "c018", "format": "cloudformation", "cloud": "aws", "difficulty": "hard", "profile": "mixed",
     "description": "S3-triggered image resizer Lambda with an encrypted bucket and scoped role, but the Lambda function URL uses AuthType NONE (YAML)."},
    {"id": "c019", "format": "cloudformation", "cloud": "aws", "difficulty": "easy", "profile": "vulnerable",
     "description": "Security group allowing Postgres port 5432 from 0.0.0.0/0, attached to a publicly accessible, unencrypted Postgres instance with no backups (YAML)."},
    {"id": "c020", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "mixed",
     "description": "VPC flow logs enabled to S3 with delivery policy and lifecycle rules, but the destination bucket is unencrypted (YAML)."},
    # --- CloudFormation JSON (c021-c025) ---
    {"id": "c021", "format": "cloudformation", "cloud": "aws", "difficulty": "easy", "profile": "vulnerable",
     "description": "S3 asset bucket with a bucket policy granting s3:GetObject to everyone, plus website hosting enabled (JSON)."},
    {"id": "c022", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "vulnerable",
     "description": "Support team IAM group with a customer-managed policy allowing all actions on all resources, attached to a user with an active access key (JSON)."},
    {"id": "c023", "format": "cloudformation", "cloud": "aws", "difficulty": "easy", "profile": "secure",
     "description": "Hardened EC2 app server: encrypted gp3 root volume, IMDSv2 required, office-only SSH/HTTPS ingress (JSON)."},
    {"id": "c024", "format": "cloudformation", "cloud": "aws", "difficulty": "medium", "profile": "vulnerable",
     "description": "Customer Postgres RDS with storage encryption and backups enabled, but publicly accessible behind an internet-open security group (JSON)."},
    {"id": "c025", "format": "cloudformation", "cloud": "aws", "difficulty": "hard", "profile": "mixed",
     "description": "Partner API on Lambda plus API Gateway with a scoped role, API key requirement and X-Ray tracing, but access logging and metrics disabled on the stage (JSON)."},
    # --- ARM JSON (c026-c040) ---
    {"id": "c026", "format": "arm", "cloud": "azure", "difficulty": "easy", "profile": "vulnerable",
     "description": "Storage account with HTTPS-only disabled, TLS 1.0, public blob access and a public container (ARM)."},
    {"id": "c027", "format": "arm", "cloud": "azure", "difficulty": "medium", "profile": "secure",
     "description": "Finance storage account: TLS 1.2, HTTPS-only, no public blob access, shared-key disabled, deny-by-default network ACLs and a private container (ARM)."},
    {"id": "c028", "format": "arm", "cloud": "azure", "difficulty": "medium", "profile": "vulnerable",
     "description": "Shared Key Vault with soft delete and purge protection disabled, open network ACLs, a full-permission legacy access policy and a seeded secret (ARM)."},
    {"id": "c029", "format": "arm", "cloud": "azure", "difficulty": "hard", "profile": "secure",
     "description": "Production Key Vault: RBAC authorization, 90-day soft delete, purge protection, no public network access and a private endpoint with private DNS zone (ARM)."},
    {"id": "c030", "format": "arm", "cloud": "azure", "difficulty": "medium", "profile": "vulnerable",
     "description": "SQL Server with TLS 1.0, public network access and a firewall rule allowing the entire IPv4 range, with no auditing configured (ARM)."},
    {"id": "c031", "format": "arm", "cloud": "azure", "difficulty": "medium", "profile": "secure",
     "description": "Billing SQL Server with AAD-only authentication, public network access disabled, TLS 1.2, auditing and transparent data encryption enabled (ARM)."},
    {"id": "c032", "format": "arm", "cloud": "azure", "difficulty": "easy", "profile": "vulnerable",
     "description": "Dev VNet with an NSG allowing RDP and SSH from any source, including the Internet service tag (ARM)."},
    {"id": "c033", "format": "arm", "cloud": "azure", "difficulty": "medium", "profile": "secure",
     "description": "Production VNet with a default-deny NSG, office-only SSH, VNet-internal allow rule, service endpoints and a bastion subnet (ARM)."},
    {"id": "c034", "format": "arm", "cloud": "azure", "difficulty": "hard", "profile": "mixed",
     "description": "Reporting storage plus secrets vault: both network-hardened with RBAC, but the vault lacks purge protection (ARM)."},
    {"id": "c035", "format": "arm", "cloud": "azure", "difficulty": "medium", "profile": "mixed",
     "description": "Analytics SQL Server with auditing and TDE enabled, but a firewall rule still opens the server to the whole internet (ARM)."},
    {"id": "c036", "format": "arm", "cloud": "azure", "difficulty": "medium", "profile": "mixed",
     "description": "Team Key Vault on legacy access policies with soft delete and deny-by-default network ACLs, but no purge protection (ARM)."},
    {"id": "c037", "format": "arm", "cloud": "azure", "difficulty": "easy", "profile": "vulnerable",
     "description": "Load-test NSG with a single rule allowing all protocols, ports and addresses inbound, attached to a test VNet (ARM)."},
    {"id": "c038", "format": "arm", "cloud": "azure", "difficulty": "easy", "profile": "vulnerable",
     "description": "Storage account with static website hosting enabled, HTTPS-only disabled, TLS 1.0 and public blob access (ARM)."},
    {"id": "c039", "format": "arm", "cloud": "azure", "difficulty": "hard", "profile": "vulnerable",
     "description": "Legacy Linux VM with an unencrypted OS disk, password authentication enabled, disabled boot diagnostics and an allow-all NSG (ARM)."},
    {"id": "c040", "format": "arm", "cloud": "azure", "difficulty": "hard", "profile": "secure",
     "description": "Payments Key Vault with RBAC, purge protection, private endpoint, private DNS zone with VNet link and a scoped secrets-user role assignment (ARM)."},
    # --- Bicep (c041-c055) ---
    {"id": "c041", "format": "bicep", "cloud": "azure", "difficulty": "easy", "profile": "vulnerable",
     "description": "Gallery storage account with HTTPS-only disabled, TLS 1.0 and public blob container access (Bicep)."},
    {"id": "c042", "format": "bicep", "cloud": "azure", "difficulty": "medium", "profile": "secure",
     "description": "Production Key Vault with RBAC authorization, purge protection, 90-day soft delete, deny-by-default network ACLs and a seeded secret (Bicep)."},
    {"id": "c043", "format": "bicep", "cloud": "azure", "difficulty": "hard", "profile": "mixed",
     "description": "Hub VNet built with subnet and NSG-rule loops; internal traffic allowed but a contractor RDP rule is open to any source (Bicep)."},
    {"id": "c044", "format": "bicep", "cloud": "azure", "difficulty": "medium", "profile": "vulnerable",
     "description": "ERP SQL Server with TLS 1.0, public network access and an allow-all firewall rule (Bicep)."},
    {"id": "c045", "format": "bicep", "cloud": "azure", "difficulty": "easy", "profile": "mixed",
     "description": "Parameter/variable/interpolation demo deploying storage with HTTPS-only and a private container, but TLS 1.0 minimum (Bicep)."},
    {"id": "c046", "format": "bicep", "cloud": "azure", "difficulty": "hard", "profile": "mixed",
     "description": "Two-file module deployment: the shared storage module is hardened, but the caller passes Blob public access for the container (Bicep)."},
    {"id": "c047", "format": "bicep", "cloud": "azure", "difficulty": "medium", "profile": "mixed",
     "description": "Audit storage with diagnostic settings sending logs to Log Analytics, but retention is only 7 days against a 90-day policy (Bicep)."},
    {"id": "c048", "format": "bicep", "cloud": "azure", "difficulty": "easy", "profile": "vulnerable",
     "description": "Dev Key Vault with no soft delete or purge protection, open network ACLs, a full-permission access policy and a seeded secret (Bicep)."},
    {"id": "c049", "format": "bicep", "cloud": "azure", "difficulty": "medium", "profile": "secure",
     "description": "NSG generated with a loop over management ports, restricted to the office CIDR with a deny-all inbound fallback, attached to a VNet (Bicep)."},
    {"id": "c050", "format": "bicep", "cloud": "azure", "difficulty": "easy", "profile": "mixed",
     "description": "Central Log Analytics workspace with 90-day retention and an alert action group, but public ingestion and query endpoints left enabled (Bicep)."},
    {"id": "c051", "format": "bicep", "cloud": "azure", "difficulty": "medium", "profile": "mixed",
     "description": "Analytics SQL Server with auditing and TDE enabled, but a firewall rule still covers the entire internet (Bicep)."},
    {"id": "c052", "format": "bicep", "cloud": "azure", "difficulty": "hard", "profile": "secure",
     "description": "Finance storage fully private: no public network access, shared-key disabled, TLS 1.2, private endpoint with private DNS zone and VNet link (Bicep)."},
    {"id": "c053", "format": "bicep", "cloud": "azure", "difficulty": "hard", "profile": "vulnerable",
     "description": "Spoke VNet peered to the hub with forwarded traffic allowed and an NSG permitting all traffic from the peered 10.0.0.0/8 range (Bicep)."},
    {"id": "c054", "format": "bicep", "cloud": "azure", "difficulty": "medium", "profile": "mixed",
     "description": "App Key Vault seeding secrets through a loop with RBAC and private networking, but purge protection disabled (Bicep)."},
    {"id": "c055", "format": "bicep", "cloud": "azure", "difficulty": "easy", "profile": "secure",
     "description": "Subscription-scoped deployment creating a tagged production resource group protected by a CanNotDelete lock (Bicep)."},
    # --- Pulumi YAML (c056-c070) ---
    {"id": "c056", "format": "pulumi", "cloud": "aws", "difficulty": "easy", "profile": "vulnerable",
     "description": "AWS S3 asset bucket with public-read ACL, website hosting and a public bucket policy (Pulumi YAML)."},
    {"id": "c057", "format": "pulumi", "cloud": "aws", "difficulty": "medium", "profile": "vulnerable",
     "description": "AWS EC2 jump box with SSH open to a default 0.0.0.0/0 CIDR and RDP open to the internet (Pulumi YAML)."},
    {"id": "c058", "format": "pulumi", "cloud": "azure", "difficulty": "easy", "profile": "secure",
     "description": "Azure storage account with TLS 1.2, HTTPS-only, no public blob or shared-key access and deny-by-default network rules (Pulumi YAML)."},
    {"id": "c059", "format": "pulumi", "cloud": "aws", "difficulty": "medium", "profile": "vulnerable",
     "description": "AWS RDS Postgres with storage encryption and backups, but publicly accessible behind an internet-open security group (Pulumi YAML)."},
    {"id": "c060", "format": "pulumi", "cloud": "azure", "difficulty": "medium", "profile": "mixed",
     "description": "Azure Key Vault with RBAC authorization, soft delete and no public network access, but purge protection disabled (Pulumi YAML)."},
    {"id": "c061", "format": "pulumi", "cloud": "aws", "difficulty": "hard", "profile": "mixed",
     "description": "AWS Lambda order processor with KMS-encrypted environment, but wildcard DynamoDB/SQS permissions, no DLQ and no tracing (Pulumi YAML)."},
    {"id": "c062", "format": "pulumi", "cloud": "azure", "difficulty": "easy", "profile": "vulnerable",
     "description": "Azure VNet with an NSG allowing RDP from any source (Pulumi YAML)."},
    {"id": "c063", "format": "pulumi", "cloud": "aws", "difficulty": "medium", "profile": "secure",
     "description": "AWS IAM least-privilege Lambda role scoped to one S3 prefix with a TLS-only condition and a source-account trust condition (Pulumi YAML)."},
    {"id": "c064", "format": "pulumi", "cloud": "azure", "difficulty": "medium", "profile": "mixed",
     "description": "Azure SQL Server with TLS 1.2, a secret admin password and an analytics database, but a firewall rule open to the whole internet (Pulumi YAML)."},
    {"id": "c065", "format": "pulumi", "cloud": "aws", "difficulty": "hard", "profile": "mixed",
     "description": "AWS two-tier VPC with a locked-down private NACL, but the public NACL allows all inbound traffic (Pulumi YAML)."},
    {"id": "c066", "format": "pulumi", "cloud": "azure", "difficulty": "easy", "profile": "vulnerable",
     "description": "Azure storage account with HTTPS-only disabled, TLS 1.0 and a public blob container (Pulumi YAML)."},
    {"id": "c067", "format": "pulumi", "cloud": "aws", "difficulty": "medium", "profile": "secure",
     "description": "AWS Lambda invoice processor with KMS-encrypted environment, scoped role, X-Ray tracing, DLQ and reserved concurrency (Pulumi YAML)."},
    {"id": "c068", "format": "pulumi", "cloud": "azure", "difficulty": "medium", "profile": "vulnerable",
     "description": "Azure Key Vault with soft delete and purge protection disabled, open network ACLs and a full-permission access policy (Pulumi YAML)."},
    {"id": "c069", "format": "pulumi", "cloud": "aws", "difficulty": "hard", "profile": "secure",
     "description": "AWS RDS Postgres production instance: SSE-KMS, Multi-AZ, private, Secrets Manager password, deletion protection and performance insights (Pulumi YAML)."},
    {"id": "c070", "format": "pulumi", "cloud": "aws", "difficulty": "hard", "profile": "mixed",
     "description": "Multi-cloud assets: the AWS S3 bucket is private, encrypted and versioned with a public-access block, while the Azure storage account allows public blob access (Pulumi YAML)."},
]

assert len(ENTRIES) == 70, f"expected 70 entries, got {len(ENTRIES)}"
assert [e["id"] for e in ENTRIES] == [f"c{i:03d}" for i in range(1, 71)], "ids must be c001..c070 in order"

REQUIRED = {"id", "format", "cloud", "difficulty", "profile", "description"}
for e in ENTRIES:
    assert set(e.keys()) == REQUIRED, f"schema mismatch: {e['id']}"
    assert e["format"] in ("cloudformation", "arm", "bicep", "pulumi"), e
    assert e["cloud"] in ("aws", "azure"), e
    assert e["difficulty"] in ("easy", "medium", "hard"), e
    assert e["profile"] in ("vulnerable", "secure", "mixed"), e
    low = e["description"].lower()
    assert "vulnerable" not in low and "secure" not in low, f"banned word in {e['id']}"


def main():
    # Fresh read immediately before writing: a sibling worker owns the k-group
    # entries in the same file, so append via read-modify-write.
    if os.path.exists(MANIFEST):
        with open(MANIFEST) as fh:
            manifest = json.load(fh)
        assert isinstance(manifest, list), "existing manifest is not a JSON array"
        existing_ids = {e["id"] for e in manifest}
        new_entries = [e for e in ENTRIES if e["id"] not in existing_ids]
        manifest.extend(new_entries)
        print(f"manifest existed ({len(manifest) - len(new_entries)} entries); appended {len(new_entries)} c-entries")
    else:
        manifest = list(ENTRIES)
        print("manifest absent; created fresh with 70 c-entries")
    with open(MANIFEST, "w") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    with open(BACKUP, "w") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")
    print(f"wrote {MANIFEST} ({len(manifest)} entries) and {BACKUP}")

    cs = [e for e in manifest if str(e.get("id", "")).startswith("c")]
    print("c-group count:", len(cs))
    print("c-group format:", dict(Counter(e["format"] for e in cs)))
    print("c-group cloud:", dict(Counter(e["cloud"] for e in cs)))
    print("c-group profile:", dict(Counter(e["profile"] for e in cs)))
    print("c-group difficulty:", dict(Counter(e["difficulty"] for e in cs)))
    print("total manifest entries:", len(manifest))


if __name__ == "__main__":
    main()
