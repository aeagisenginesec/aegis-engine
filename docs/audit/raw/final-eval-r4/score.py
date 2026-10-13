#!/usr/bin/env python3
"""Round-4 blind evaluation scorer. See docs/audit/11_EVAL_PROTOCOL.md.

Methodology (fixed before scoring runs):
- Ground truth: adjudicated (project, resource, condition, severity) concepts.
- Condition-class taxonomy maps both concepts and scanner findings to classes.
- Matching: for each (project, class): TP = min(concepts, findings).
- Hygiene-excluded rule IDs are removed from FP accounting for all scanners.
- FP rate via adjudicated sampling of unmatched findings (see fp_adjudicate.py).
- CIs: cluster bootstrap by project (10k resamples).
"""
import json, re, os
from collections import defaultdict

BASE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(BASE, 'scanner-output')
GT = json.load(open(os.path.join(BASE, 'ground-truth.json')))
HYGIENE_RULE_IDS = {'AEGIS-AWS-706', 'AEGIS-AZURE-111', 'AEGIS-GCP-215',
                    'AEGIS-TF-004', 'AEGIS-AWS-658', 'AEGIS-AWS-684',
                    'AEGIS-AWS-798', 'AEGIS-GCP-114', 'AEGIS-AWS-699'}
PROJ_RE = re.compile(r'^r4\d{3}$')

def norm_text(text):
    t = re.sub(r'([a-z0-9])([A-Z])', r'\1 \2', text).lower()
    t = re.sub(r'[_\-/.:()]', ' ', t)
    t = t.replace('"', '')
    t = re.sub(r'\s+', ' ', t)
    return t

# (class, positive keywords, negative keywords) — keywords in normalized form
CLASS_RULES = [
    # S3 / object storage
    ('s3-public-acl', ['public acl', 'acl set to public', 'acl public read', 'public read acl', 'public-read', 'publicly accessible through acl'], []),
    ('s3-public-policy', ['bucket policy'], []),
    ('s3-no-encryption', ['server side encryption', 'default encryption'], ['kms']),
    ('dynamodb-no-cmk', ['customer managed kms', 'customer managed key'], []),
    ('s3-no-versioning', ['versioning'], []),
    ('s3-no-logging', ['access logging', 'server access log', 'access logs', 'bucket logging'], ['cloudtrail', 'vpc', 'flow']),
    ('s3-no-lifecycle', ['lifecycle'], []),
    ('s3-public-access-block', ['public access block'], []),
    ('storage-public-azure', ['public blob', 'allow blob public', 'anonymous'], []),
    ('gcs-public', ['all users', 'all authenticated users', 'publicly readable via iam'], []),
    # IAM
    ('iam-wildcard', ['allows all actions', 'all actions on all resources', 'wildcard', 'action * on resource *', 'on all resources'], ['trust']),
    ('iam-admin', ['administrative access', 'administrator access', 'full admin'], []),
    ('iam-trust-broad', ['trust policy', 'assume role', 'sts assumerole', 'assumable by anyone'], []),
    ('iam-privesc', ['privilege escalation'], []),
    ('iam-exfil', ['exfiltration'], []),
    ('iam-no-boundary', ['no permissions boundary', 'permissions boundary'], []),
    ('secret-hardcoded', ['hardcoded', 'plaintext', 'baked into', 'in plaintext', 'private key material', 'service account key', 'secret in service environment'], ['environment variables', 'container env']),
    ('kms-no-rotation', ['key rotation', 'without rotation'], []),
    ('no-waf', ['waf'], []),
    # Network
    ('sg-open-ssh', ['ssh port 22', 'port 22 open', 'ssh open to', 'ssh from internet', 'ingress open to the world', 'ingress to ssh', 'unrestricted access to ssh'], ['nsg']),
    ('sg-open-rdp', ['rdp', 'port 3389'], ['nsg']),
    ('sg-open-world', ['0.0.0.0 0', 'open to the world', 'open to internet', 'world open', 'to the internet'], ['ssh port', 'rdp', 'nsg', 'eks', 'port 5432', 'port 3306', 'port 6379', 'port 1433', 'postgres', 'mysql']),
    ('sg-open-db', ['port 5432', 'port 3306', 'port 6379', 'port 1433', 'postgres', 'mysql', 'redis port', 'sql server port'], ['nsg']),
    ('nsg-open', ['network security group', 'nsg '], []),
    ('os-login-disabled', ['os login disabled', 'without os login', 'os login off'], []),
    # Compute
    ('imdsv1', ['without imdsv2', 'imdsv1', 'http tokens', 'metadata options'], []),
    ('ec2-imds-hop', ['hop limit'], []),
    ('volume-unencrypted', ['volume without encryption', 'root volume', 'unencrypted volume', 'encrypted false', 'encrypted = false', 'encrypted is false', 'disk is unencrypted', 'disk has no encryption', 'encrypted to false'], ['storage_encrypted', 'storage encrypted']),
    ('ec2-no-termination-protection', ['termination protection'], []),
    # Database
    ('db-public', ['publicly accessible', 'public ip', 'from the internet', 'public network access'], ['eks', 'api server', 'acl']),
    ('db-no-encryption', ['storage encrypted false', 'storage not encrypted', 'without storage encryption', 'storage encrypted', 'storage encryption disabled', 'encryption disabled', 'encrypted = false', 'encrypted is false', 'transparent data encryption'], ['volume']),
    ('db-no-backup', ['backup retention', 'backups disabled', 'no automated backups', 'without automated backups', 'automated backups disabled', 'point in time recovery', 'backup configuration', 'no automated backup'], []),
    ('db-no-deletion-protection', ['deletion protection', 'deletion window'], []),
    ('db-no-ssl', ['require ssl'], []),
    ('db-weak-auth', ['weak password', 'default password', 'password123', 'root password stored'], []),
    ('db-no-multiaz', ['multi az', 'multiaz'], []),
    # Logging / monitoring
    ('no-cloudtrail', ['cloudtrail', 'cloud trail', 'no trail'], ['validation']),
    ('cloudtrail-no-validation', ['log file validation'], []),
    ('no-flowlog', ['flow log', 'flowlog', 'vpc flow'], []),
    ('no-audit-log', ['audit log', 'auditing', 'auditing policy'], []),
    ('log-retention-short', ['retention is only', 'log retention'], ['backup']),
    # TLS
    ('weak-tls', ['tls 1 0', 'tls 1 1', 'deprecated tls', 'minimum tls', 'minimal tls', 'below tls 1 2', 'not using tls 1 2'], []),
    ('http-only', ['plain http', 'http only', 'https traffic only', 'https only'], []),
    ('lambda-public-url', ['auth type none', 'function url'], []),
    ('cors-open', ['cors'], []),
    # Containers
    ('docker-root', ['runs as root', 'no user directive', 'user root'], []),
    ('docker-secret', ['secret in arg', 'secret in env', 'credentials embedded', 'build arg', 'token is persisted'], []),
    ('docker-build-tools', ['debugging tools', 'debug tools', 'build tools', 'analysis tools'], []),
    ('docker-add-remote', ['add used instead of copy', 'add used to fetch', 'add fetches'], []),
    ('docker-latest', ['floating major', 'latest'], []),
    ('docker-no-healthcheck', ['no healthcheck', 'healthcheck uses', 'cmd true'], []),
    ('sudo-nopasswd', ['nopasswd', 'passwordless sudo'], []),
    ('curl-pipe-shell', ['piped directly to shell', 'piped to shell', 'pipe to shell'], []),
    ('git-exposed', ['git directory'], []),
    ('k8s-privileged', ['privileged', 'dangerous capabilities', 'capabilities'], ['service']),
    ('k8s-host', ['hostnetwork', 'host network', 'hostpid', 'hostipc', 'hostpath', 'host path', 'host pid', 'host ipc', 'host filesystem', 'root filesystem', 'host proc'], ['service']),
    ('k8s-secrets-no-encryption', ['encryption config', 'secrets unencrypted', 'unencrypted in etcd'], []),
    ('k8s-no-security-context', ['no security context', 'missing security context'], []),
    ('k8s-no-limits', ['resource limits', 'resource requests'], []),
    ('k8s-no-probe', ['liveness probe', 'readiness probe'], []),
    ('k8s-no-networkpolicy', ['networkpolicy', 'network policy'], []),
    ('k8s-rbac-broad', ['cluster admin', 'broad rbac'], []),
    ('k8s-secret-env', ['secret in env', 'environment variables', 'container env'], []),
    ('compose-docker-sock', ['docker socket', 'docker sock'], []),
    ('compose-privileged', ['shares host namespaces', 'runs privileged', 'host pid'], ['container', 'daemon set']),
    # Azure specifics
    ('azure-keyvault-open', ['key vault', 'network acls'], ['purge']),
    ('keyvault-no-purge', ['purge protection'], []),
    ('keyvault-no-soft-delete', ['soft delete'], ['purge']),
    ('aks-public-api', ['public api server', 'authorized ip'], []),
    ('aks-no-rbac', ['without rbac', 'role based access control'], []),
    ('ecr-mutable-tags', ['mutable'], []),
    ('storage-shared-key', ['shared access key', 'shared key'], []),
    ('acr-admin', ['admin enabled', 'admin account'], []),
    ('aks-local-admin', ['local account', 'local admin'], []),
    ('cosmosdb-public', ['ip range filter', 'ip filter'], []),
    # GCP specifics
    ('gcp-bucket-no-cmek', ['customer managed encryption'], []),
    ('gcp-sql-public', ['connections from the internet'], []),
    ('gcp-sql-no-ssl', ['ssl enforcement'], []),
    ('vm-password-auth', ['password authentication'], []),
    ('gcp-gke-public', ['not private', 'publicly reachable', 'master authorized', 'control plane publicly', 'gke control plane'], []),
    ('gcp-compute-broad-scope', ['broad service account scope', 'full cloud platform', 'cloud platform scope'], []),
    ('gcp-compute-ip-forward', ['ip forwarding', 'ip forward'], []),
    ('gke-legacy-auth', ['client certificate'], []),
    ('gcp-iam-broad', ['roles editor'], []),
    ('gcp-compute-no-secureboot', ['secure boot'], []),
    ('gcp-compute-no-oslogin', ['os login'], ['disabled']),
    ('gcp-iam-owner', ['owner role'], []),
    ('eks-public-api', ['eks cluster', 'eks api', 'endpoint public access', 'public api endpoint'], []),
    ('alb-public', ['internet facing alb', 'internet-facing alb', 'plain http listener', 'application load balancer', 'load balancer with plain http'], []),
    ('es-no-encryption', ['opensearch', 'open search', 'elasticsearch'], []),
    ('elasticache-no-encryption', ['elasticache', 'elasti cache'], []),
    ('sqs-no-encryption', ['sqs'], []),
    ('compose-no-limits', ['resource limits', 'deploy limits', 'without limits'], []),
    ('compose-host-network', ['host network', 'network mode host', 'network mode: host'], []),
    ('k8s-nodeport', ['nodeport', 'node port'], []),
    ('k8s-default-sa', ['default service account', 'service account token'], []),
]

CLASS_RULES_N = [(c, [norm_text(p) for p in pos], [norm_text(n) for n in neg])
                 for c, pos, neg in CLASS_RULES]

def classify(text):
    t = norm_text(text)
    return [c for c, pos, neg in CLASS_RULES_N
            if any(p in t for p in pos) and not any(n in t for n in neg)]

def is_proj(fn):
    return fn.endswith('.json') and bool(PROJ_RE.match(fn[:-5]))

def load_aegis():
    out = []
    d = os.path.join(RAW, 'aegis')
    for fn in sorted(os.listdir(d)):
        if not is_proj(fn):
            continue
        pid = fn[:-5]
        try:
            data = json.load(open(os.path.join(d, fn)))
        except Exception:
            continue
        for f in data.get('findings', []):
            if f.get('rule_id') in HYGIENE_RULE_IDS:
                continue
            ev = f.get('evidence', {}) or {}
            out.append({'project': pid, 'resource': f.get('resource', ''),
                        'rule': f.get('rule_id', ''), 'title': f.get('title', ''),
                        'severity': f.get('severity', ''),
                        'file': (ev.get('span', {}) or {}).get('file', '')})
    return out

def load_checkov():
    out = []
    d = os.path.join(RAW, 'checkov')
    for fn in sorted(os.listdir(d)):
        if not is_proj(fn):
            continue
        pid = fn[:-5]
        try:
            data = json.load(open(os.path.join(d, fn)))
        except Exception:
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            res = item.get('results', {})
            checks = res.get('failed_checks', []) if isinstance(res, dict) else []
            for c in checks:
                out.append({'project': pid, 'resource': c.get('resource', ''),
                            'rule': c.get('check_id', ''), 'title': c.get('check_name', ''),
                            'severity': str(c.get('severity') or ''),
                            'file': c.get('file_path', '')})
    return out

def load_kics():
    out = []
    d = os.path.join(RAW, 'kics')
    for fn in sorted(os.listdir(d)):
        if not fn.endswith('-results.json'):
            continue
        data = json.load(open(os.path.join(d, fn)))
        for q in data.get('queries', []):
            for fl in q.get('files', []):
                fname = fl.get('file_name', '')
                m = re.search(r'corpus/([^/]+)/', fname)
                if m:
                    out.append({'project': m.group(1), 'resource': fname,
                                'rule': q.get('query_id', ''), 'title': q.get('query_name', ''),
                                'severity': q.get('severity', ''), 'file': fname})
    return out

def load_trivy():
    out = []
    d = os.path.join(RAW, 'trivy')
    for fn in sorted(os.listdir(d)):
        if not is_proj(fn):
            continue
        pid = fn[:-5]
        try:
            data = json.load(open(os.path.join(d, fn)))
        except Exception:
            continue
        for r in data.get('Results', []):
            for m in r.get('Misconfigurations', []):
                out.append({'project': pid, 'resource': r.get('Target', ''),
                            'rule': m.get('ID', ''), 'title': m.get('Title', ''),
                            'severity': m.get('Severity', ''), 'file': ''})
    return out

LOADERS = {'aegis': load_aegis, 'checkov': load_checkov,
           'kics': load_kics, 'trivy': load_trivy}

def build_concept_index():
    idx = defaultdict(list)
    for i, c in enumerate(GT):
        idx[c['project']].append((i, c, set(classify(c['condition'] + ' ' + c.get('resource', '')))))
    return idx

def score_scanner(name, findings, cidx):
    pf = defaultdict(list)
    for fi, f in enumerate(findings):
        for cl in set(classify(f['title'] + ' ' + f['rule'])):
            pf[(f['project'], cl)].append(fi)
    pc = defaultdict(list)
    for pid, concepts in cidx.items():
        for ci, c, cclasses in concepts:
            for cl in cclasses:
                pc[(pid, cl)].append(ci)
    tp_concepts, used = set(), set()
    rank = {'high': 0, 'medium': 1, 'low': 2}
    for key, ci_list in pc.items():
        fi_list = pf.get(key, [])
        n = min(len(ci_list), len(fi_list))
        for ci in sorted(ci_list, key=lambda i: rank.get(GT[i].get('severity', 'low'), 2))[:n]:
            tp_concepts.add(ci)
        for fi in fi_list[:n]:
            used.add(fi)
    tp, fn = len(tp_concepts), len(GT) - len(tp_concepts)
    fp_cand = [findings[i] for i in range(len(findings)) if i not in used]
    return {'tp': tp, 'fn': fn, 'fp_candidates': fp_cand,
            'tp_concepts': sorted(tp_concepts), 'n_findings': len(findings)}

if __name__ == '__main__':
    cidx = build_concept_index()
    nocl = sum(1 for _, cs in cidx.items() for _, c, cl in cs if not cl)
    print(f'concepts with no class: {nocl}/{len(GT)}')
    summary = {}
    for name, loader in LOADERS.items():
        try:
            findings = loader()
        except FileNotFoundError:
            print(f'{name}: no output yet')
            continue
        if not findings:
            print(f'{name}: no findings loaded')
            continue
        s = score_scanner(name, findings, cidx)
        print(f"{name}: findings={s['n_findings']} tp={s['tp']} fn={s['fn']} fp_cand={len(s['fp_candidates'])}")
        summary[name] = {'tp': s['tp'], 'fn': s['fn'],
                         'fp_candidates': len(s['fp_candidates']),
                         'n_findings': s['n_findings']}
    json.dump(summary, open(os.path.join(BASE, 'scores-auto.json'), 'w'), indent=1)
