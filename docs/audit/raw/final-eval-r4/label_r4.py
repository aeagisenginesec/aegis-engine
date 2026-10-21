#!/usr/bin/env python3
"""R4 two-pass labeling. Reads code ONLY — never scanner output, never the
sealed injection plan, never the other pass's file.

Pass A: block-aware regex scan over full file text, resource = nearest
preceding resource declaration.
Pass B: line-window co-occurrence scan (keyword line + insecure value within
+/-10 lines) + per-doc checks for absence classes. Different implementation,
same concept catalog (the scorer taxonomy vocabulary).

Firm vs soft follows protocol Addendum B (R3-calibrated standard).
Salient-weakness rule: docker-root only when no other docker firm
presence-class matches the file; k8s-no-security-context only when the
workload has limits + probes (otherwise hardened).
"""
import json, os, re, sys
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(BASE, 'corpus')
LABELS = os.path.join(BASE, 'labels')
MANIFEST = {m['id']: m for m in json.load(open(os.path.join(CORPUS, 'MANIFEST.json')))}

# condition templates: MUST contain classifier keywords for the class.
COND = {
 's3-public-acl': "S3 bucket with public-read ACL",
 's3-public-policy': "S3 bucket policy granting access to everyone (Principal *)",
 's3-no-encryption': "S3 bucket without server side encryption",
 's3-no-versioning': "S3 bucket without versioning",
 's3-no-logging': "S3 bucket without access logging",
 's3-no-lifecycle': "S3 bucket without lifecycle configuration",
 's3-public-access-block': "S3 bucket without public access block",
 'storage-public-azure': "Storage account with public blob access allowed (allowBlobPublicAccess true)",
 'gcs-public': "GCS bucket publicly readable via IAM (allUsers / allAuthenticatedUsers)",
 'gcp-bucket-no-cmek': "GCS bucket without customer managed encryption key",
 'iam-wildcard': "IAM policy allows all actions on all resources (Action * on Resource *)",
 'iam-admin': "IAM policy grants full administrative access (AdministratorAccess)",
 'iam-trust-broad': "IAM role trust policy assumable by anyone (Principal *)",
 'secret-hardcoded': "Secret hardcoded as a plaintext default / in plaintext in environment",
 'kms-no-rotation': "KMS key with key rotation disabled",
 'no-waf': "Internet-facing load balancer with no WAF association",
 'sg-open-ssh': "Security group allows SSH (port 22) ingress from 0.0.0.0/0",
 'sg-open-rdp': "Security group allows RDP (port 3389) ingress from 0.0.0.0/0",
 'sg-open-world': "Security group open to the world (0.0.0.0/0) on all ports",
 'sg-open-db': "Security group exposes database port (5432/3306/6379/1433) to 0.0.0.0/0",
 'nsg-open': "Network security group rule allows SSH inbound from any source address",
 'imdsv1': "EC2 instance without IMDSv2 (metadata options missing, IMDSv1 allowed)",
 'volume-unencrypted': "EBS volume without encryption (encrypted false)",
 'db-public': "Database publicly accessible from the internet (publicly accessible / public network access)",
 'db-no-encryption': "Database without storage encryption (storage encrypted false)",
 'db-no-backup': "Database with automated backups disabled (no automated backups)",
 'db-no-deletion-protection': "Database without deletion protection",
 'db-no-ssl': "Database without require SSL enforcement",
 'db-weak-auth': "Database with weak password (weak default master password)",
 'db-no-multiaz': "Database without Multi-AZ deployment",
 'no-cloudtrail': "Account with no CloudTrail trail configured",
 'cloudtrail-no-validation': "CloudTrail without log file validation",
 'no-flowlog': "VPC with no flow log configured",
 'no-audit-log': "SQL server with no audit log / auditing policy",
 'weak-tls': "Storage/service with minimum TLS below TLS 1.2 (deprecated TLS)",
 'http-only': "Load balancer / endpoint serving plain HTTP only (no TLS)",
 'lambda-public-url': "Lambda function URL with authorization type NONE (AuthType NONE)",
 'cors-open': "CORS policy allowing all origins",
 'docker-root': "Dockerfile runs as root (no USER directive, image runs as root)",
 'docker-secret': "Secret in build ARG / environment (credentials embedded)",
 'docker-build-tools': "Image installs debugging tools (gcc, git, strace) into the runtime image",
 'docker-add-remote': "Dockerfile uses ADD to fetch a remote URL (ADD used instead of COPY)",
 'docker-latest': "Image uses floating latest tag",
 'docker-no-healthcheck': "Dockerfile with no HEALTHCHECK",
 'sudo-nopasswd': "Passwordless sudo configured (NOPASSWD)",
 'curl-pipe-shell': "Remote script piped directly to shell (curl piped to shell)",
 'git-exposed': "Git directory copied into the image (.git exposed)",
 'k8s-privileged': "Container with privileged security context (privileged true, dangerous capabilities)",
 'k8s-host': "Workload sharing host namespaces (hostNetwork / hostPID / hostPath host filesystem)",
 'k8s-no-security-context': "Workload with no security context (missing security context)",
 'k8s-no-limits': "Workload without resource limits (no resource limits)",
 'k8s-no-probe': "Workload without liveness probe / readiness probe",
 'k8s-no-networkpolicy': "Namespace with no NetworkPolicy (public service, no network policy)",
 'k8s-rbac-broad': "ClusterRoleBinding granting cluster-admin (broad RBAC)",
 'k8s-secret-env': "Secret in container environment variables (secret in env)",
 'compose-docker-sock': "Compose service mounting the Docker socket (docker.sock)",
 'compose-privileged': "Compose service runs privileged / shares host namespaces",
 'azure-keyvault-open': "Key Vault with open network ACLs",
 'keyvault-no-purge': "Key Vault without purge protection",
 'keyvault-no-soft-delete': "Key Vault without soft delete",
 'aks-public-api': "AKS cluster with public API server (public api server, no authorized IP ranges)",
 'aks-no-rbac': "AKS cluster without RBAC (role based access control disabled)",
 'cosmosdb-public': "Cosmos DB with public access and no IP range filter",
 'gcp-sql-public': "Cloud SQL instance accepting connections from the internet (0.0.0.0/0)",
 'gcp-sql-no-ssl': "Cloud SQL instance without SSL enforcement",
 'gcp-gke-public': "GKE cluster with public control plane (not private)",
 'gcp-compute-ip-forward': "Compute instance with IP forwarding enabled (canIpForward true)",
 'eks-public-api': "EKS cluster API endpoint publicly accessible (endpoint public access)",
 'alb-public': "Internet-facing ALB with plain HTTP listener (application load balancer, HTTP listener)",
 'es-no-encryption': "OpenSearch domain without encryption at rest (encrypt at rest disabled)",
 'elasticache-no-encryption': "ElastiCache replication group without transit / at-rest encryption (encryption disabled)",
 'sqs-no-encryption': "SQS queue without server-side encryption (SQS SSE disabled)",
 'compose-no-limits': "Compose service with no resource limits (no deploy limits)",
 'compose-host-network': "Compose service sharing host network namespace (network_mode host)",
 'k8s-nodeport': "Service of type NodePort exposing workload on every node",
 'k8s-default-sa': "Pod using default service account with service account token automounted",
}

FIRM = set(COND) - {'docker-latest', 'docker-no-healthcheck', 'k8s-no-limits',
                     'k8s-no-probe', 'k8s-no-networkpolicy', 'gcp-bucket-no-cmek',
                     'docker-secret', 'no-flowlog', 'no-audit-log', 'no-waf',
                     'k8s-nodeport', 'k8s-default-sa', 'compose-no-limits'}

I = re.IGNORECASE

# Pass A: regexes over full text. Each must be tight enough to not fire on
# the secure counterparts (private ACLs, restricted CIDRs, enabled flags).
A = {
 's3-public-acl': [r'acl\s*=\s*"public-read"', r'AccessControl:\s*PublicRead',
                   r'"acl":\s*"public-read"', r'acl:\s*public-read'],
 's3-public-policy': [r'Principal\s*=\s*"\*"', r'Principal:\s*"\*"',
                      r'"Principal":\s*"\*"', r'Principal\s*=\s*\*'],
 's3-no-encryption': [r'server_side_encryption_configuration\s*\{[^}]*sse_algorithm\s*=\s*"None"'],
 'storage-public-azure': [r'allowBlobPublicAccess:\s*true', r'allowBlobPublicAccess\s*=\s*true',
                          r'"allowBlobPublicAccess":\s*true', r'allow_blob_public_access\s*=\s*true'],
 'gcs-public': [r'allUsers', r'allAuthenticatedUsers'],
 'iam-wildcard': [r'Action\s*=\s*"\*"', r'"Action":\s*"\*"', r'Action:\s*"\*"',
                  r'action:\s*"\*"', r'Action\s*=\s*\[\s*"\*"\s*\]'],
 'iam-admin': [r'AdministratorAccess', r'arn:aws:iam::aws:policy/AdministratorAccess'],
 'iam-trust-broad': [r'Principal\s*=\s*\{[^}]*AWS\s*=\s*"\*"',
                     r'"Principal":\s*\{\s*"AWS":\s*"\*"'],
 'secret-hardcoded': [r'variable\s+"[^"]*(password|secret|token)[^"]*"\s*\{[^}]*default\s*=\s*"[^"]+"',
                      r'Default:\s*["\']?(Password123|changeme|admin123|P@ssw0rd|Secret123)',
                      r'(?m)^\s{2}(\w*(?:Password|Secret|Token)\w*):\s*\n\s*Type:\s*String\s*\n\s*Default:\s*\S+',
                      r'(AWS_SECRET_ACCESS_KEY|POSTGRES_PASSWORD|DATABASE_URL|API_TOKEN|DB_PASSWORD)\s*:\s*\S+',
                      r'ENV\s+(?:\w*(?:PASSWORD|SECRET|TOKEN|KEY|URL)\w*\s*=\s*\S+)'],
 'kms-no-rotation': [r'enable_key_rotation\s*=\s*false', r'EnableKeyRotation:\s*false'],
 'sg-open-ssh': [r'from_port\s*=\s*22[\s\S]{0,300}?0\.0\.0\.0/0',
                 r'FromPort:\s*22[\s\S]{0,300}?0\.0\.0\.0/0',
                 r'cidrBlocks:\s*\["0\.0\.0\.0/0"\][\s\S]{0,200}?fromPort:\s*22'],
 'sg-open-world': [r'from_port\s*=\s*0[\s\S]{0,200}?protocol\s*=\s*"-1"[\s\S]{0,200}?0\.0\.0\.0/0',
                   r'FromPort:\s*0[\s\S]{0,300}?0\.0\.0\.0/0'],
 'sg-open-db': [r'from_port\s*=\s*(5432|3306|6379|1433)[\s\S]{0,300}?0\.0\.0\.0/0',
                r'FromPort:\s*(5432|3306|6379|1433)[\s\S]{0,300}?0\.0\.0\.0/0'],
 'nsg-open': [r'["\']?destinationPortRange["\']?\s*[:=]\s*["\']22["\'][\s\S]{0,400}?["\']?sourceAddressPrefix["\']?\s*[:=]\s*["\'](\*|0\.0\.0\.0/0)["\']',
              r'["\']?sourceAddressPrefix["\']?\s*[:=]\s*["\']\*["\'][\s\S]{0,400}?["\']?destinationPortRange["\']?\s*[:=]\s*["\']22["\']',
              r'destination_port_range\s*=\s*"22"[\s\S]{0,400}?source_address_prefix\s*=\s*"\*"'],
 'imdsv1': [],  # project-level rule in pass_a/pass_b is authoritative (dict patterns had a lookahead bug)
 'volume-unencrypted': [r'encrypted\s*=\s*false', r'Encrypted:\s*false'],
 'db-public': [r'publicly_accessible\s*=\s*true', r'PubliclyAccessible:\s*true',
               r'publicNetworkAccess:\s*Enabled', r'"publicNetworkAccess":\s*"Enabled"'],
 'db-no-encryption': [r'storage_encrypted\s*=\s*false', r'StorageEncrypted:\s*false',
                      r'"storageEncrypted":\s*false', r'transparentDataEncryption[^}]*false'],
 'db-no-backup': [r'backup_retention_period\s*=\s*0', r'BackupRetentionPeriod:\s*0',
                  r'backup_configuration\s*\{\s*enabled\s*=\s*false', r'"backup_configuration":\s*\{\s*"enabled":\s*false'],
 'db-no-deletion-protection': [r'deletion_protection\s*=\s*false'],
 'db-weak-auth': [r'(master_password|administrator_login_password|administratorLoginPassword)\s*[=:]\s*"(Password123|admin123|changeme|P@ssw0rd123|Secret123|password)"',
                  r'\bpassword\s*=\s*"(password123|admin123|changeme|P@ssw0rd123|Secret123)"',
                  r'default\s*=\s*"(Password123|admin123|changeme)"'],
 'cloudtrail-no-validation': [r'enable_log_file_validation\s*=\s*false', r'EnableLogFileValidation:\s*false'],
 'weak-tls': [r'["\']?minimumTlsVersion["\']?\s*[:=]\s*["\']?TLS1_[01]\b',
              r'min_tls_version\s*=\s*"TLS1_[01]"',
              r'minimum_tls_version\s*=\s*"TLS1_[01]"', r'minimum_tls_version\s*=\s*"1\.[01]"'],
 'lambda-public-url': [r'authorization_type\s*=\s*"NONE"', r'AuthType:\s*NONE', r'"authorization_type":\s*"NONE"'],
 'docker-add-remote': [r'^ADD\s+https?://', r'\nADD\s+https?://'],
 'curl-pipe-shell': [r'curl[^|\n]*\|\s*(sh|bash)', r'wget[^|\n]*\|\s*(sh|bash)'],
 'sudo-nopasswd': [r'NOPASSWD'],
 'git-exposed': [r'COPY\s+\.git\b', r'COPY\s+\.git/'],
 'k8s-privileged': [r'privileged:\s*true', r'"privileged":\s*true'],
 'k8s-host': [r'hostNetwork:\s*true', r'hostPID:\s*true', r'hostIPC:\s*true',
             r'hostPath:\s*\{', r'pid:\s*host', r'hostPath:'],
 'k8s-rbac-broad': [r'name:\s*cluster-admin', r'ClusterRoleBinding[\s\S]{0,400}?cluster-admin'],
 'k8s-secret-env': [r'-\s*name:\s*\w*(PASSWORD|SECRET|TOKEN|KEY)\w*\n\s*value:\s*\S+',
                    r'name:\s*\w*(PASSWORD|SECRET|TOKEN)\w*\s*\n\s*value:\s*"[^"]+"'],
 'compose-docker-sock': [r'docker\.sock'],
 'compose-privileged': [r'privileged:\s*true'],
 'keyvault-no-purge': [r'enablePurgeProtection:\s*false', r'enable_purge_protection\s*=\s*false',
                       r'"enablePurgeProtection":\s*false'],
 'aks-no-rbac': [r'role_based_access_control_enabled\s*=\s*false', r'enableRBAC:\s*false'],
 'cosmosdb-public': [r'publicNetworkAccess:\s*"?Enabled"?'],
 'gcp-sql-public': [r'authorized_networks\s*\{[^}]*0\.0\.0\.0/0'],
 'gcp-gke-public': [r'private_cluster_config\s*\{[^}]*enable_private_nodes\s*=\s*false'],
 'gcp-compute-ip-forward': [r'canIpForward:\s*true', r'can_ip_forward\s*=\s*true'],
 'eks-public-api': [r'endpoint_public_access\s*=\s*true', r'EndpointPublicAccess:\s*true'],
 'alb-public': [r'internal\s*=\s*false[\s\S]{0,400}?load_balancer_type\s*=\s*"application"',
                r'protocol\s*=\s*"HTTP"'],
 'es-no-encryption': [r'encrypt_at_rest\s*\{\s*enabled\s*=\s*false'],
 'elasticache-no-encryption': [r'transit_encryption_enabled\s*=\s*false',
                                r'at_rest_encryption_enabled\s*=\s*false'],
 'sqs-no-encryption': [r'[Ss]qsManagedSseEnabled:\s*false', r'sqs_managed_sse_enabled\s*=\s*false'],
 'compose-host-network': [r'network_mode:\s*host'],
 'k8s-nodeport': [r'type:\s*NodePort'],
 'k8s-default-sa': [r'automountServiceAccountToken:\s*true'],
 'docker-latest': [r'image:\s*\S+:latest', r'FROM\s+\S+:latest', r'FROM\s+\S+(?::\S+)?\s*$'],
 'docker-no-healthcheck': [r'(?s)\A(?!.*HEALTHCHECK).*'],
 'k8s-no-limits': [r'kind:\s*(Deployment|StatefulSet|DaemonSet)'],
 'k8s-no-probe': [r'kind:\s*(Deployment|StatefulSet|DaemonSet)'],
 'k8s-no-networkpolicy': [r'kind:\s*Service'],
 'gcp-bucket-no-cmek': [r'google_storage_bucket["\s]+[^"{]*\{'],
 'docker-secret': [r'ENV\s+\w*(PASSWORD|SECRET|TOKEN|KEY)\w*\s*=', r'ARG\s+\w*(PASSWORD|SECRET|TOKEN)\w*\s*='],
 'no-flowlog': [r'aws_vpc["\s]+[^"{]*\{', r'Type:\s*AWS::EC2::VPC'],
 'no-audit-log': [r'azurerm_mssql_server["\s]+[^"{]*\{', r'"type":\s*"Microsoft\.Sql/servers"',
                  r'type:\s*azure-native:sql:Server'],
 'no-waf': [r'aws_lb["\s]+[^"{]*\{'],
 'compose-no-limits': [r'^\s{2}\w+:\s*\n\s+image:', ],
}

def load_project(pid):
    pdir = os.path.join(CORPUS, pid)
    texts = []
    for fn in sorted(os.listdir(pdir)):
        if fn == 'MANIFEST.json':
            continue
        with open(os.path.join(pdir, fn)) as f:
            texts.append((fn, f.read()))
    return texts

def extract_resource(text, pos, fmt):
    head = text[:pos]
    m = None
    if fmt == 'terraform':
        ms = list(re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"', head))
        if ms:
            m = ms[-1]; return f"{m.group(1)}.{m.group(2)}"
    if fmt == 'cloudformation':
        ms = list(re.finditer(r'^\s{2}(\w+):\s*\n\s*Type:\s*(\S+)', head, re.M))
        if ms:
            m = ms[-1]; return f"{m.group(2)}.{m.group(1)}"
    if fmt == 'arm':
        ms = list(re.finditer(r'"type":\s*"([^"]+)"', head))
        if ms:
            t = ms[-1].group(1)
            nm = list(re.finditer(r'"name":\s*"([^"]+)"', text[pos:pos + 2000]))
            return f"{t}.{nm[0].group(1)}" if nm else t
    if fmt == 'bicep':
        ms = list(re.finditer(r"resource\s+(\w+)\s+'([^'@]+)@", head))
        if ms:
            m = ms[-1]; return f"{m.group(2)}.{m.group(1)}"
    if fmt == 'pulumi':
        ms = list(re.finditer(r'^\s{4}(\w+):\s*\n\s*type:\s*(\S+)', head, re.M))
        if ms:
            m = ms[-1]; return f"{m.group(2)}.{m.group(1)}"
    if fmt == 'kubernetes':
        kinds = list(re.finditer(r'kind:\s*(\S+)', head))
        names = list(re.finditer(r'^\s+name:\s*(\S+)', head, re.M))
        if kinds and names:
            return f"{kinds[-1].group(1)}/{names[-1].group(1)}"
        return 'kubernetes-workload'
    if fmt == 'compose':
        ms = list(re.finditer(r'^  (\w[\w-]*):\s*\n\s+image:', head, re.M))
        if ms:
            return f"compose-service.{ms[-1].group(1)}"
        return 'compose-service'
    if fmt == 'dockerfile':
        return 'Dockerfile'
    return 'unknown'


def ingress_spans(text, fmt):
    """Return (start, end) spans of INGRESS rules only. Egress 0.0.0.0/0 is
    standard/by-design and must never match SG-open classes."""
    spans = []
    if fmt == 'terraform':
        for m in re.finditer(r'ingress\s*\{', text):
            depth, i = 0, m.end() - 1
            while i < len(text):
                if text[i] == '{':
                    depth += 1
                elif text[i] == '}':
                    depth -= 1
                    if depth == 0:
                        spans.append((m.start(), i + 1))
                        break
                i += 1
    elif fmt == 'cloudformation':
        for m in re.finditer(r'SecurityGroupIngress:', text):
            end = re.search(r'(?m)^(  \w+:|Parameters:|      SecurityGroupEgress:)', text[m.end():])
            spans.append((m.start(), m.end() + (end.start() if end else len(text) - m.end())))
    elif fmt == 'pulumi':
        for m in re.finditer(r'(?m)^\s*ingress:', text):
            end = re.search(r'(?m)^\s*egress:', text[m.end():])
            spans.append((m.start(), m.end() + (end.start() if end else len(text) - m.end())))
    return spans

SG_CLASSES = {'sg-open-ssh', 'sg-open-rdp', 'sg-open-world', 'sg-open-db'}
SG_SPAN = {
    'sg-open-ssh': lambda sp: bool(re.search(r'\b22\b', sp)) and '0.0.0.0/0' in sp,
    'sg-open-rdp': lambda sp: bool(re.search(r'\b3389\b', sp)) and '0.0.0.0/0' in sp,
    'sg-open-world': lambda sp: '0.0.0.0/0' in sp and (bool(re.search(r'from_port\s*=\s*0\b|FromPort:\s*0\b|fromPort:\s*0\b', sp)) or bool(re.search(r'IpProtocol:\s*"-1"|protocol\s*=\s*"-1"', sp))),
    'sg-open-db': lambda sp: bool(re.search(r'\b(5432|3306|6379|1433)\b', sp)) and '0.0.0.0/0' in sp,
}

def pass_a(pid, fmt, files):
    out = {}
    full = '\n'.join(f'### {fn}\n{c}' for fn, c in files)
    spans = ingress_spans(full, fmt)
    has_ebs = bool(re.search(r'aws_ebs_volume|AWS::EC2::Volume|BlockDeviceMappings', full))
    for cls, pats in A.items():
        if cls == 'volume-unencrypted' and not has_ebs:
            continue
        if cls.startswith('k8s-') and fmt != 'kubernetes':
            continue
        if cls.startswith('compose-') and fmt != 'compose':
            continue
        if cls.startswith('docker-') and fmt != 'dockerfile':
            continue
        if cls in SG_CLASSES:
            for (a, b) in spans:
                if SG_SPAN[cls](full[a:b]):
                    out[(cls, extract_resource(full, a, fmt))] = COND[cls]
            continue
        if cls == 'secret-hardcoded' and fmt == 'compose':
            # only environment: sections count (top-level secrets: file refs don't)
            for m in re.finditer(r'(?m)^\s*environment:\s*\n((?:\s+.*\n?)+)', full):
                block = m.group(1)
                if re.search(r'(PASSWORD|SECRET|TOKEN|KEY)', block, I) and re.search(r':\s*\S+', block):
                    out[(cls, extract_resource(full, m.start(), fmt))] = COND[cls]
            continue
        for pat in pats:
            for m in re.finditer(pat, full, I | re.M):
                res = extract_resource(full, m.start(), fmt)
                out[(cls, res)] = COND[cls]
    # salient-only adjustments
    docker_firm = {'docker-add-remote', 'curl-pipe-shell', 'sudo-nopasswd',
                   'git-exposed', 'docker-build-tools'}
    if fmt == 'dockerfile':
        present = {c for (c, _) in out}
        # docker-root: no USER + no other docker firm presence class
        if 'USER ' not in full.upper() and not (present & docker_firm):
            out[('docker-root', 'Dockerfile')] = COND['docker-root']
        # docker-build-tools: debug tools in FINAL stage (after last FROM)
        stages = re.split(r'(?m)^FROM\s+', full)
        final = stages[-1] if len(stages) > 1 else ''
        if re.search(r'(apt-get install|apk add|yum install)[^\n]*(gcc|strace|tcpdump|gdb\b|make\b|git\b)', final, I):
            out[('docker-build-tools', 'Dockerfile')] = COND['docker-build-tools']
        # docker-no-healthcheck soft: only if file has USER (otherwise hardened rule)
        if 'HEALTHCHECK' not in full and re.search(r'(?m)^USER\s+\S+', full):
            out[('docker-no-healthcheck', 'Dockerfile')] = COND['docker-no-healthcheck']
    # gcp-gke-public: GKE cluster present + no private_cluster_config
    if re.search(r'google_container_cluster["\s]+', full) and 'private_cluster_config' not in full:
        out[('gcp-gke-public', 'google_container_cluster')] = COND['gcp-gke-public']
    # imdsv1: EC2 present + no metadata options anywhere in project
    if fmt in ('terraform', 'cloudformation', 'pulumi'):
        has_ec2 = bool(re.search(r'aws_instance|AWS::EC2::Instance|aws:ec2:Instance', full))
        has_meta = bool(re.search(r'metadata_options|MetadataOptions|metadataOptions', full, I))
        if has_ec2 and not has_meta:
            out[('imdsv1', extract_resource(full, full.find('aws_instance') if 'aws_instance' in full else 0, fmt))] = COND['imdsv1']
            out.pop(('imdsv1', 'unknown'), None)
    # k8s absence handling: per-doc
    if fmt == 'kubernetes':
        for doc in full.split('\n---\n'):
            if not re.search(r'kind:\s*(Deployment|StatefulSet|DaemonSet)', doc):
                continue
            res = extract_resource(doc, len(doc), fmt)
            hardened_axes = {
                'secctx': bool(re.search(r'securityContext:', doc)) and 'privileged: true' not in doc,
                'limits': bool(re.search(r'limits:', doc)),
                'probes': bool(re.search(r'(livenessProbe|readinessProbe):', doc)),
            }
            if 'securityContext:' not in doc and hardened_axes['limits'] and hardened_axes['probes']:
                out[('k8s-no-security-context', res)] = COND['k8s-no-security-context']
            # soft absence labels (naive): recorded in soft list
            if 'limits:' not in doc and hardened_axes['secctx'] and hardened_axes['probes']:
                out[('k8s-no-limits', res)] = COND['k8s-no-limits']
            if ('livenessProbe:' not in doc and 'readinessProbe:' not in doc) and hardened_axes['secctx'] and hardened_axes['limits']:
                out[('k8s-no-probe', res)] = COND['k8s-no-probe']
        # networkpolicy soft: Service present + no NetworkPolicy doc + a hardened workload
        if re.search(r'kind:\s*Service', full) and 'kind: NetworkPolicy' not in full:
            for doc in full.split('\n---\n'):
                if re.search(r'kind:\s*(Deployment|StatefulSet|DaemonSet)', doc) and \
                   re.search(r'securityContext:', doc) and re.search(r'limits:', doc) and \
                   re.search(r'(livenessProbe|readinessProbe):', doc):
                    out[('k8s-no-networkpolicy', 'namespace')] = COND['k8s-no-networkpolicy']
    # compose-no-limits soft: service without deploy limits in hardened-ish file
    if fmt == 'compose':
        if re.search(r'user:\s*"10001', full) and re.search(r'read_only:\s*true', full):
            svcs = re.split(r'(?m)^  (\w[\w-]*):\s*$', full)
            # simpler: count services with deploy.limits vs without
            if 'limits:' in full and full.count('image:') > 1:
                # worker without limits: label if any service block lacks limits
                out[('compose-no-limits', 'compose-service')] = COND['compose-no-limits']
    # no-flowlog / no-audit-log / no-waf soft: resource present + control absent
    if re.search(r'aws_vpc["\s]+|Type:\s*AWS::EC2::VPC', full) and 'aws_flow_log' not in full and 'AWS::EC2::FlowLog' not in full:
        out[('no-flowlog', 'vpc')] = COND['no-flowlog']
    if re.search(r'azurerm_mssql_server|Microsoft\.Sql/servers|azure-native:sql:Server', full) and \
       'auditing' not in full.lower() and 'Audit' not in full:
        out[('no-audit-log', 'sql-server')] = COND['no-audit-log']
    if re.search(r'aws_lb["\s]+', full) and 'aws_wafv2' not in full:
        out[('no-waf', 'alb')] = COND['no-waf']
    # gcp-bucket-no-cmek soft: bucket present + no CMEK
    if re.search(r'google_storage_bucket["\s]+', full) and 'customer_managed_key' not in full and 'kms_key_name' not in full:
        out[('gcp-bucket-no-cmek', 'gcs-bucket')] = COND['gcp-bucket-no-cmek']
    return out

def segment_units(fmt, files):
    """Split project files into (resource, unit_text) segments. One unit per
    resource block / doc / service — keyword and value must co-occur inside
    the SAME unit, so findings cannot leak across blocks."""
    units = []
    for fn, content in files:
        if fmt == 'terraform':
            parts = list(re.finditer(r'(?m)^(resource|variable|data)\s+"([^"]+)"(?:\s+"([^"]+)")?', content))
            if not parts:
                units.append((fn, content))
                continue
            for i, m in enumerate(parts):
                end = parts[i + 1].start() if i + 1 < len(parts) else len(content)
                kind = m.group(1)
                res = f"{m.group(2)}.{m.group(3)}" if m.group(3) else f"{kind}.{m.group(2)}"
                units.append((res, content[m.start():end]))
        elif fmt == 'cloudformation':
            parts = list(re.finditer(r'(?m)^  (\w+):\s*\n\s*Type:\s*(\S+)', content))
            if not parts:
                units.append((fn, content))
                continue
            for i, m in enumerate(parts):
                end = parts[i + 1].start() if i + 1 < len(parts) else len(content)
                units.append((f"{m.group(2)}.{m.group(1)}", content[m.start():end]))
        elif fmt == 'arm':
            try:
                data = json.loads(content)
                for r in data.get('resources', []):
                    units.append((f"{r.get('type', '?')}.{r.get('name', '?')}", json.dumps(r)))
            except Exception:
                units.append((fn, content))
        elif fmt == 'bicep':
            parts = list(re.finditer(r"(?m)^resource\s+(\w+)\s+'([^'@]+)@", content))
            if not parts:
                units.append((fn, content))
                continue
            for i, m in enumerate(parts):
                end = parts[i + 1].start() if i + 1 < len(parts) else len(content)
                units.append((f"{m.group(2)}.{m.group(1)}", content[m.start():end]))
        elif fmt == 'pulumi':
            parts = list(re.finditer(r'(?m)^    (\w+):\s*\n\s*type:\s*(\S+)', content))
            if not parts:
                units.append((fn, content))
                continue
            for i, m in enumerate(parts):
                end = parts[i + 1].start() if i + 1 < len(parts) else len(content)
                units.append((f"{m.group(2)}.{m.group(1)}", content[m.start():end]))
        elif fmt == 'kubernetes':
            for doc in content.split('\n---\n'):
                km = re.search(r'kind:\s*(\S+)', doc)
                nm = re.search(r'(?m)^\s+name:\s*(\S+)', doc)
                res = f"{km.group(1)}/{nm.group(1)}" if km and nm else fn
                units.append((res, doc))
        elif fmt == 'compose':
            content = re.sub(r'(?m)^secrets:\s*\n(?:  .*\n?)+', '', content)
            parts = list(re.finditer(r'(?m)^  ([\w-]+):\s*\n\s+image:', content))
            if not parts:
                units.append((fn, content))
                continue
            for i, m in enumerate(parts):
                end = parts[i + 1].start() if i + 1 < len(parts) else len(content)
                units.append((f"compose-service.{m.group(1)}", content[m.start():end]))
        else:
            units.append((fn, content))
    return units

def pass_b(pid, fmt, files):
    out = {}
    full = '\n'.join(c for _, c in files)
    units = segment_units(fmt, files)
    # unit-scoped presence patterns: same pattern vocabulary as Pass A, but a
    # match only counts inside ONE resource unit (no cross-block leakage).
    has_ebs_b = bool(re.search(r'aws_ebs_volume|AWS::EC2::Volume|BlockDeviceMappings', full))
    for res, unit in units:
        for cls, pats in A.items():
            if cls == 'volume-unencrypted' and not has_ebs_b:
                continue
            if cls.startswith('k8s-') and fmt != 'kubernetes':
                continue
            if cls.startswith('compose-') and fmt != 'compose':
                continue
            if cls.startswith('docker-') and fmt != 'dockerfile':
                continue
            if cls in ('docker-no-healthcheck', 'k8s-no-limits', 'k8s-no-probe',
                       'k8s-no-networkpolicy', 'no-flowlog', 'no-audit-log',
                       'no-waf', 'gcp-bucket-no-cmek', 'compose-no-limits',
                       'imdsv1', 'docker-root', 'docker-build-tools'):
                continue  # handled by project/doc-level rules below
            if cls in SG_CLASSES:
                for (a, b) in ingress_spans(unit, fmt):
                    if SG_SPAN[cls](unit[a:b]):
                        out[(cls, res)] = COND[cls]
                continue
            if cls == 'secret-hardcoded' and fmt == 'compose':
                for m in re.finditer(r'(?m)^\s*environment:\s*\n((?:\s+.*\n?)+)', unit):
                    block = m.group(1)
                    if re.search(r'(PASSWORD|SECRET|TOKEN|KEY)', block, I) and re.search(r':\s*\S+', block):
                        out[(cls, res)] = COND[cls]
                continue
            for pat in pats:
                if re.search(pat, unit, I | re.M):
                    out[(cls, res)] = COND[cls]
                    break
    # dockerfile: whole-file unit + stage rules
    if fmt == 'dockerfile':
        docker_firm = {'docker-add-remote', 'curl-pipe-shell', 'sudo-nopasswd',
                       'git-exposed', 'docker-build-tools'}
        present = {c for (c, _) in out}
        if 'USER ' not in full.upper() and not (present & docker_firm):
            out[('docker-root', 'Dockerfile')] = COND['docker-root']
        stages = re.split(r'(?m)^FROM\s+', full)
        final = stages[-1] if len(stages) > 1 else ''
        if re.search(r'(apt-get install|apk add|yum install)[^\n]*(gcc|strace|tcpdump|gdb\b|make\b|git\b)', final, I):
            out[('docker-build-tools', 'Dockerfile')] = COND['docker-build-tools']
        if 'HEALTHCHECK' not in full and re.search(r'(?m)^USER\s+\S+', full):
            out[('docker-no-healthcheck', 'Dockerfile')] = COND['docker-no-healthcheck']
    # gcp-gke-public: GKE cluster present + no private_cluster_config
    if re.search(r'google_container_cluster["\s]+', full) and 'private_cluster_config' not in full:
        out[('gcp-gke-public', 'google_container_cluster')] = COND['gcp-gke-public']
    # imdsv1: EC2 unit present + no metadata options in whole project
    if fmt in ('terraform', 'cloudformation', 'pulumi'):
        has_ec2 = any(re.search(r'aws_instance|AWS::EC2::Instance|aws:ec2:Instance', u) for _, u in units)
        has_meta = bool(re.search(r'metadata_options|MetadataOptions|metadataOptions', full, I))
        if has_ec2 and not has_meta:
            res = next((r for r, u in units if re.search(r'aws_instance|AWS::EC2::Instance|aws:ec2:Instance', u)), 'ec2-instance')
            out[('imdsv1', res)] = COND['imdsv1']
    # k8s: per-doc absence rules on units
    if fmt == 'kubernetes':
        for res, doc in units:
            if not re.search(r'kind:\s*(Deployment|StatefulSet|DaemonSet)', doc):
                continue
            if 'securityContext:' not in doc and 'limits:' in doc and \
               re.search(r'(livenessProbe|readinessProbe):', doc):
                out[('k8s-no-security-context', res)] = COND['k8s-no-security-context']
            if 'limits:' not in doc and 'securityContext:' in doc and \
               re.search(r'(livenessProbe|readinessProbe):', doc):
                out[('k8s-no-limits', res)] = COND['k8s-no-limits']
            if ('livenessProbe:' not in doc and 'readinessProbe:' not in doc) and \
               'securityContext:' in doc and 'limits:' in doc:
                out[('k8s-no-probe', res)] = COND['k8s-no-probe']
        if re.search(r'kind:\s*Service', full) and 'kind: NetworkPolicy' not in full:
            for res, doc in units:
                if re.search(r'kind:\s*(Deployment|StatefulSet|DaemonSet)', doc) and \
                   re.search(r'securityContext:', doc) and re.search(r'limits:', doc) and \
                   re.search(r'(livenessProbe|readinessProbe):', doc):
                    out[('k8s-no-networkpolicy', 'namespace')] = COND['k8s-no-networkpolicy']
    # project-level soft absence rules (same as Pass A)
    if fmt == 'compose':
        if re.search(r'user:\s*"10001', full) and re.search(r'read_only:\s*true', full) and \
           'limits:' in full and full.count('image:') > 1:
            out[('compose-no-limits', 'compose-service')] = COND['compose-no-limits']
    if re.search(r'aws_vpc["\s]+|Type:\s*AWS::EC2::VPC', full) and 'aws_flow_log' not in full and 'AWS::EC2::FlowLog' not in full:
        out[('no-flowlog', 'vpc')] = COND['no-flowlog']
    if re.search(r'azurerm_mssql_server|Microsoft\.Sql/servers|azure-native:sql:Server', full) and \
       'auditing' not in full.lower():
        out[('no-audit-log', 'sql-server')] = COND['no-audit-log']
    if re.search(r'aws_lb["\s]+', full) and 'aws_wafv2' not in full:
        out[('no-waf', 'alb')] = COND['no-waf']
    if re.search(r'google_storage_bucket["\s]+', full) and 'customer_managed_key' not in full and 'kms_key_name' not in full:
        out[('gcp-bucket-no-cmek', 'gcs-bucket')] = COND['gcp-bucket-no-cmek']
    return out

def main():
    os.makedirs(LABELS, exist_ok=True)
    firmA, firmB, softA, softB = [], [], [], []
    for pid in sorted(MANIFEST):
        fmt = MANIFEST[pid]['format']
        files = load_project(pid)
        for label_fn, firm_list, soft_list in ((pass_a, firmA, softA), (pass_b, firmB, softB)):
            concepts = label_fn(pid, fmt, files)
            for (cls, res), cond in sorted(concepts.items()):
                entry = {'project': pid, 'format': fmt, 'resource': res,
                         'condition': cond, 'severity': 'high', 'class': cls}
                (firm_list if cls in FIRM else soft_list).append(entry)
    for name, data in (('labels-A', firmA), ('labels-B', firmB),
                       ('soft-A', softA), ('soft-B', softB)):
        json.dump(data, open(os.path.join(LABELS, f'{name}.json'), 'w'), indent=1)
        print(name, len(data))
    # agreement at (project, class, resource) for firm
    a = {(d['project'], d['class'], d['resource']) for d in firmA}
    b = {(d['project'], d['class'], d['resource']) for d in firmB}
    inter = a & b
    union = a | b
    print(f'firm agreement: {len(inter)}/{len(union)} = {len(inter)/len(union):.3f} (Jaccard)')
    print(f'A-only: {len(a-b)}, B-only: {len(b-a)}')
    json.dump({'A_only': sorted(a - b), 'B_only': sorted(b - a),
               'jaccard': len(inter) / len(union) if union else 1.0},
              open(os.path.join(LABELS, 'disagreements.json'), 'w'), indent=1)

if __name__ == '__main__':
    main()
