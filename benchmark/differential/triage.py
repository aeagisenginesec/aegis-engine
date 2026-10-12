#!/usr/bin/env python3
"""
Differential benchmark triage tool: Aegis vs KICS vs Checkov.

Takes JSON outputs from all three scanners for the same corpus and groups
findings into:
  Group A: findings all three detect (normalized by resource + issue type)
  Group B: findings only Aegis detects
  Group C: findings only KICS and/or Checkov detect
  Group D: findings that cannot be compared reliably

Usage:
  python3 triage.py --aegis aegis.json --kics kics_results.json \
      --checkov checkov.json --out differential_report.md \
      [--mapping rule_mapping.json]

Rule mapping: explicit mappings in rule_mapping.json, plus heuristic
fuzzy matching on titles. Unmapped findings fall to Group D when they
cannot be normalized reliably.
"""

import argparse
import json
import os
import re
import sys
from collections import defaultdict

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ---------------------------------------------------------------- parsers

def parse_aegis(path):
    """Aegis JSON: {"findings": [{rule_id, title, severity, resource, evidence{span{file}}}]}"""
    with open(path) as f:
        d = json.load(f)
    findings = d.get("findings", d if isinstance(d, list) else [])
    out = []
    for x in findings:
        ev = x.get("evidence", {}) or {}
        span = ev.get("span", {}) or {}
        out.append({
            "scanner": "aegis",
            "rule_id": x.get("rule_id", ""),
            "title": x.get("title", ""),
            "severity": (x.get("severity") or "info").lower(),
            "resource": x.get("resource", ""),
            "file": span.get("file", ""),
            "attribute": ev.get("attribute", ""),
        })
    return out


def parse_kics(path):
    """KICS JSON: {"queries": [{query_id, query_name, severity, files: [{...}]}]}
    When resource_name is a ${...} reference, the primary resource is the
    referenced resource; the declaring resource_type is stored as an alias
    (KICS attributes policy findings to the referenced bucket; Aegis
    attributes to the policy resource)."""
    with open(path) as f:
        d = json.load(f)
    out = []
    for q in d.get("queries", []):
        qid = q.get("query_id", "")
        qname = q.get("query_name", "")
        sev = (q.get("severity") or "info").lower()
        for fl in q.get("files", []):
            primary, aliases = extract_kics_resources(fl)
            out.append({
                "scanner": "kics",
                "rule_id": qid,
                "title": qname,
                "severity": sev,
                "resource": primary,
                "aliases": aliases,
                "file": fl.get("file_name", ""),
                "attribute": "",
            })
    return out


def extract_kics_resources(file_entry):
    """Return (primary, aliases) normalized resource addresses.
    Handles ${...} references: primary is the referenced resource;
    alias is declaring_type.referenced_name (e.g. aws_s3_bucket_policy.pp3)
    so it matches the specific policy resource, not just the type."""
    rtype = (file_entry.get("resource_type") or "").strip()
    rname = (file_entry.get("resource_name") or "").strip().strip("'\"")
    m = re.match(r"^\$\{(.+)\}$", rname)
    if m:
        inner = normalize_resource(m.group(1))
        # extract name from inner address for the alias
        iname = inner.split(".")[-1] if "." in inner else ""
        aliases = []
        if rtype and iname:
            aliases.append(normalize_resource(f"{rtype}.{iname}"))
        elif rtype:
            aliases.append(normalize_resource(rtype))
        return inner, aliases
    if rtype and rname:
        return normalize_resource(f"{rtype}.{rname}"), []
    if rtype:
        return normalize_resource(rtype), []
    for k in ("resource_address", "resource"):
        if file_entry.get(k):
            return normalize_resource(str(file_entry[k])), []
    fn = file_entry.get("file_name", "")
    ln = file_entry.get("line", file_entry.get("line_number", 0))
    return f"__file__:{os.path.basename(fn)}:{ln}", []


def extract_kics_resource(file_entry):
    """Single-resource variant for backwards compatibility."""
    primary, _ = extract_kics_resources(file_entry)
    return primary


def parse_checkov(path):
    """Checkov JSON: {"results": {"failed_checks": [{check_id, check_name, resource, file_path, repo_file_path, severity}]}}"""
    with open(path) as f:
        d = json.load(f)
    # handle both single-result and list forms
    results = d.get("results", d)
    if isinstance(d, list):
        failed = []
        for entry in d:
            failed.extend(entry.get("results", {}).get("failed_checks", []))
    else:
        failed = results.get("failed_checks", [])
    out = []
    for x in failed:
        sev = x.get("severity")
        if isinstance(sev, dict):
            sev = sev.get("level", "info")
        sev = (sev or "info").lower()
        out.append({
            "scanner": "checkov",
            "rule_id": x.get("check_id", ""),
            "title": x.get("check_name", ""),
            "severity": sev,
            "resource": x.get("resource", ""),
            "file": x.get("repo_file_path", x.get("file_path", "")),
            "attribute": "",
        })
    return out

# ------------------------------------------------------- normalization

def normalize_resource(addr):
    """Normalize a Terraform resource address:
    - strip interpolation: ${aws_s3_bucket.foo.id} -> aws_s3_bucket.foo
    - strip module prefixes: module.foo.aws_s3_bucket.bar -> aws_s3_bucket.bar
    - strip array indices: aws_s3_bucket.bar[0] -> aws_s3_bucket.bar
    - strip trailing attribute: aws_s3_bucket.foo.id -> aws_s3_bucket.foo
    - lowercase the type portion
    """
    if not addr:
        return ""
    a = addr.strip()
    if a.startswith("__file__:"):
        return a
    # strip ${...} interpolation wrappers (may be quoted)
    a = a.strip("'\"")
    m = re.match(r"^\$\{(.+)\}$", a)
    if m:
        a = m.group(1)
    parts = a.split(".")
    # strip module prefixes
    while len(parts) > 2 and parts[0] == "module":
        parts = parts[2:]
    # strip [N] indices
    parts = [re.sub(r"\[\d+\]$", "", p) for p in parts]
    # strip trailing attribute references (id, arn, etc.) — keep type.name
    if len(parts) > 2 and not parts[-1].startswith("aws_"):
        # last part is likely an attribute, not a resource name
        # but careful: type.name.attr vs module-less long chains
        # keep only if we can identify type.name pattern
        if len(parts) == 3 and "_" in parts[0]:
            parts = parts[:2]
    if len(parts) >= 2:
        return parts[-2].lower() + "." + parts[-1]
    return ".".join(parts).lower()


def resource_type_of(norm_addr):
    """Extract resource type from normalized address."""
    if not norm_addr or norm_addr.startswith("__file__:"):
        return ""
    return norm_addr.split(".")[0] if "." in norm_addr else ""


# Generic words that don't identify a specific service; excluded from
# type-compatibility checks to avoid false matches like
# docdb_cluster -> "Redshift cluster unencrypted" via "cluster".
_GENERIC_TYPE_WORDS = {
    "cluster", "instance", "bucket", "group", "policy", "role", "key",
    "table", "queue", "topic", "stream", "function", "database",
    "repository", "registry", "endpoint", "gateway", "listener",
    "target", "log", "alarm", "metric", "dashboard", "snapshot",
    "volume", "image", "domain", "distribution", "certificate",
    "secret", "parameter", "rule", "schedule", "task", "service",
    "deployment", "state", "machine", "user", "permission", "access",
}


def type_keywords(rtype):
    """Distinctive keyword set from a resource type, e.g.
    aws_docdb_cluster -> {docdb}. Generic words excluded."""
    t = rtype.lower()
    for prefix in ("aws_", "azurerm_", "google_", "alicloud_", "oci_"):
        if t.startswith(prefix):
            t = t[len(prefix):]
            break
    words = {w for w in re.split(r"[_\-]", t) if w and w not in ("aws",)}
    return words - _GENERIC_TYPE_WORDS


def normalize_title(t):
    """Lowercase, strip punctuation, collapse whitespace."""
    t = (t or "").lower()
    t = re.sub(r"[^a-z0-9 ]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


SYNONYMS = {
    "disabled": "without", "enabled": "with",
    "encrypted": "encryption", "unencrypted": "encryption",
    "unrestricted": "open", "exposed": "open",
    "publicly": "public", "world": "open",
    "not": "", "no": "",
}

def canonicalize_word(w):
    return SYNONYMS.get(w, w)


def title_keywords(t, stop=None):
    stop = stop or {
        "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with",
        "without", "should", "not", "be", "are", "is", "ensure", "check",
        "that", "aws", "resource", "used", "use", "all",
    }
    words = set()
    for w in normalize_title(t).split():
        if w in stop or len(w) < 2:
            continue
        c = canonicalize_word(w)
        if c:
            words.add(c)
    return words

# ------------------------------------------------------- rule mapping

def load_mapping(path):
    """rule_mapping.json: {"kics": {query_id_or_name: aegis_rule_id},
    "checkov": {check_id: aegis_rule_id}}"""
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {"kics": {}, "checkov": {}}


def build_fuzzy_index(aegis_rules):
    """keyword sets per Aegis rule for fuzzy title matching.
    Title only (rule IDs add noise); synonyms canonicalized."""
    idx = {}
    for r in aegis_rules:
        kw = title_keywords(r.get("title", ""))
        idx[r["id"]] = kw
    return idx


# Map resource type prefixes to Aegis rule provider prefixes
_PROVIDER_MAP = {
    "aws_": "AWS", "azurerm_": "AZURE", "google_": "GCP",
    "alicloud_": "ALI", "oci_": "OCI",
    "docker_": "DOCKER", "kubernetes_": "K8S",
}


def provider_of_resource(rtype):
    for prefix, prov in _PROVIDER_MAP.items():
        if rtype.startswith(prefix):
            return prov
    return ""


def provider_of_rule(rule_id):
    m = re.match(r"AEGIS-([A-Z]+)-", rule_id)
    return m.group(1) if m else ""


def map_finding(f, mapping, fuzzy_idx):
    """Return the canonical Aegis rule ID for a finding, or None if
    no confident mapping exists."""
    scanner = f["scanner"]
    if scanner == "aegis":
        return f["rule_id"]
    # explicit mapping first
    m = mapping.get(scanner, {})
    key = f["rule_id"]
    if key in m:
        return m[key]
    # also try title-keyed mapping for KICS (query names are stable)
    tkey = f["title"]
    if tkey in m:
        return m[tkey]
    # fuzzy: best Jaccard overlap on title keywords, requiring
    # resource-type AND provider compatibility
    fkw = title_keywords(f["title"])
    if not fkw:
        return None
    nr = normalize_resource(f["resource"])
    frtype = resource_type_of(nr)
    frtype_kw = type_keywords(frtype)
    fprov = provider_of_resource(frtype)
    best, best_score = None, 0.0
    for rid, kw in fuzzy_idx.items():
        if not kw:
            continue
        # provider compatibility: rule provider must match resource provider
        if fprov and provider_of_rule(rid) != fprov:
            continue
        # resource-type compatibility
        if frtype_kw:
            rkw = title_keywords(rid.replace("-", " ").replace("_", " "))
            type_overlap = bool(frtype_kw & (kw | rkw))
            title_has_type = bool(kw & _KNOWN_TYPE_WORDS)
            if title_has_type and not type_overlap:
                continue
        inter = len(fkw & kw)
        union = len(fkw | kw)
        score = inter / union if union else 0
        if score > best_score:
            best, best_score = rid, score
    # require reasonable overlap; synonyms canonicalized so 0.3 is meaningful
    return best if best_score >= 0.30 else None


# Common resource-type words appearing in rule titles; used to decide
# whether a rule is type-specific (needs type overlap) or generic.
_KNOWN_TYPE_WORDS = {
    "s3", "bucket", "ec2", "instance", "rds", "db", "lambda", "iam",
    "kms", "key", "vpc", "subnet", "security", "group", "elb", "alb",
    "nlb", "cloudtrail", "cloudwatch", "ebs", "volume", "snapshot",
    "redshift", "elasticsearch", "opensearch", "mq", "broker", "sqs",
    "sns", "kinesis", "dynamodb", "efs", "fsx", "neptune", "docdb",
    "aurora", "athena", "emr", "glue", "sagemaker", "ecs", "eks",
    "fargate", "apigateway", "api", "gateway", "cloudfront", "waf",
    "route53", "acm", "certificate", "secretsmanager", "secret",
    "ssm", "parameter", "dms", "transfer", "codebuild", "codepipeline",
    "cognito", "guardduty", "config", "macie", "detective", "securityhub",
    "backup", "ami", "launch", "autoscaling", "asg", "nat", "igw",
    "nacl", "flow", "log", "vpc", "endpoint", "peering", "transit",
    "directconnect", "vpn", "client", "directory", "workspaces",
    "appstream", "elasticache", "memorydb", "timestream", "qldb",
    "managedblockchain", "kafka", "msk", "iot", "greengrass",
    "robomaker", "lex", "polly", "transcribe", "rekognition",
    "textract", "comprehend", "forecast", "personalize", "kendra",
    "elasticsearch", "opensearch", "firehose", "kinesis",
}

# ------------------------------------------------------- grouping

def group_findings(aegis, kics, checkov, mapping, aegis_rules):
    fuzzy_idx = build_fuzzy_index(aegis_rules)
    all_f = aegis + kics + checkov

    # normalize each finding -> (norm_resource, canonical_rule or None)
    keyed = []
    for f in all_f:
        nr = normalize_resource(f["resource"])
        cr = map_finding(f, mapping, fuzzy_idx)
        keyed.append((f, nr, cr))

    groups = {"A": [], "B": [], "C": [], "D": []}
    # group by (norm_resource, canonical_rule)
    buckets = defaultdict(list)
    d_bucket = []
    # alias index: (alias_resource, rule) -> bucket key, for cross-attribution
    alias_index = {}
    for f, nr, cr in keyed:
        if not nr or cr is None or nr.startswith("__file__:"):
            # cannot be compared reliably across scanners
            d_bucket.append((f, nr, cr))
        else:
            buckets[(nr, cr)].append(f)
            for alias in f.get("aliases", []):
                if alias and not alias.startswith("__file__:"):
                    alias_index[(alias, cr)] = (nr, cr)

    # merge: if a bucket's key matches an alias of another bucket with the
    # same rule, merge them (cross-scanner resource attribution difference).
    # Type-only aliases (e.g. "aws_s3_bucket_policy") match any bucket key
    # with the same type and rule.
    def alias_matches(alias_key, bucket_key):
        ares, arule = alias_key
        bres, brule = bucket_key
        if arule != brule:
            return False
        if ares == bres:
            return True
        # type-only alias matches type.name
        if "." not in ares and bres.startswith(ares + "."):
            return True
        return False

    # Fallback: for unmatched buckets, try fuzzy resource name matching
    # (KICS uses bucket names like "u2-unenc"; Aegis uses labels like "u2").
    def fuzzy_resource_match(res1, res2):
        """True if same type and names are prefix-related."""
        t1, n1 = res1.split(".", 1) if "." in res1 else (res1, "")
        t2, n2 = res2.split(".", 1) if "." in res2 else (res2, "")
        if t1 != t2 or not n1 or not n2:
            return False
        # prefix match in either direction (u2 vs u2-unenc)
        return n1.startswith(n2) or n2.startswith(n1)

    bucket_keys = list(buckets.keys())
    merged = set()
    for akey in alias_index:
        for bkey in bucket_keys:
            if bkey in merged:
                continue
            if alias_matches(akey, bkey):
                # find the bucket that owns this alias
                owner_key = alias_index[akey]
                # don't merge a bucket into itself
                if owner_key in buckets and owner_key != bkey:
                    buckets[bkey].extend(buckets.pop(owner_key))
                    merged.add(owner_key)
                    break

    # Second pass: fuzzy resource matching for remaining Group C candidates
    # (only within same rule, to avoid false positives)
    remaining_c = []
    for key in list(buckets.keys()):
        if key in merged:
            continue
        nr, cr = key
        fs = buckets[key]
        scanners = {f["scanner"] for f in fs}
        if "aegis" not in scanners and len(scanners) == 1:
            remaining_c.append(key)

    for ckey in remaining_c:
        if ckey in merged or ckey not in buckets:
            continue
        cnr, ccr = ckey
        for bkey in bucket_keys:
            if bkey in merged or bkey == ckey or bkey not in buckets:
                continue
            bnr, bcr = bkey
            if bcr != ccr:
                continue
            bscanners = {f["scanner"] for f in buckets[bkey]}
            if "aegis" not in bscanners:
                continue
            if fuzzy_resource_match(cnr, bnr):
                buckets[bkey].extend(buckets.pop(ckey))
                merged.add(ckey)
                break

    for key, fs in buckets.items():
        scanners = {f["scanner"] for f in fs}
        if scanners == {"aegis", "kics", "checkov"}:
            groups["A"].append({"key": key, "findings": fs})
        elif scanners == {"aegis"}:
            groups["B"].append({"key": key, "findings": fs})
        elif "aegis" not in scanners:
            groups["C"].append({"key": key, "findings": fs})
        else:
            # detected by Aegis + one other: count as A (shared detection)
            groups["A"].append({"key": key, "findings": fs})

    groups["D"] = [{"key": ("uncomparable", i), "findings": [f]}
                   for i, (f, _, _) in enumerate(d_bucket)]
    return groups

# ------------------------------------------------------- report

def sev_of(group):
    sevs = [SEV_RANK.get(f["severity"], 0) for f in group["findings"]]
    return max(sevs) if sevs else 0


def write_report(groups, out_path, sample_n=30):
    inv = {v: k for k, v in SEV_RANK.items()}
    total = sum(len(v) for v in groups.values())

    def top(group_list, n=15):
        s = sorted(group_list, key=sev_of, reverse=True)[:n]
        lines = []
        for g in s:
            nr, cr = g["key"]
            fs = g["findings"]
            scanners = sorted({f["scanner"] for f in fs})
            titles = sorted({f["title"] for f in fs})
            sevs = sorted({f["severity"] for f in fs}, key=lambda s: -SEV_RANK.get(s, 0))
            lines.append(
                f"- **{nr}** / `{cr}` — {', '.join(sevs)} "
                f"(scanners: {', '.join(scanners)}; n={len(fs)})\n"
                f"  - {'; '.join(titles[:2])}"
            )
        return "\n".join(lines)

    # Group C sample for manual labeling: highest severity first
    c_sorted = sorted(groups["C"], key=sev_of, reverse=True)
    sample = c_sorted[:sample_n]
    sample_lines = []
    for i, g in enumerate(sample, 1):
        nr, cr = g["key"]
        fs = g["findings"]
        scanners = sorted({f["scanner"] for f in fs})
        sevs = sorted({f["severity"] for f in fs}, key=lambda s: -SEV_RANK.get(s, 0))
        titles = sorted({f["title"] for f in fs})
        files = sorted({f["file"] for f in fs if f["file"]})
        sample_lines.append(
            f"### C-{i:02d}: {nr} / {cr}\n"
            f"- Severity: {', '.join(sevs)} | Scanners: {', '.join(scanners)}\n"
            f"- Titles: {'; '.join(titles)}\n"
            f"- Files: {'; '.join(files[:3])}\n"
            f"- **Label:** _[real miss / duplicate / unsupported / false positive / scope mismatch]_\n"
        )

    md = f"""# Differential Triage Report: Aegis vs KICS vs Checkov

## Summary

| Group | Meaning | Buckets |
|---|---|---|
| A | Detected by all three | {len(groups['A'])} |
| B | Only Aegis detects | {len(groups['B'])} |
| C | Only KICS and/or Checkov detect | {len(groups['C'])} |
| D | Cannot be compared reliably | {len(groups['D'])} |
| **Total buckets** | | {total} |

> Buckets are (normalized resource, canonical rule) pairs. A bucket may
> contain multiple raw findings (e.g. KICS duplicates).

## Group A — shared detection (top 15 by severity)

{top(groups['A'])}

## Group B — Aegis-only (top 15 by severity)

{top(groups['B'])}

## Group C — KICS/Checkov-only (top 15 by severity)

{top(groups['C'])}

## Group C sample for manual labeling ({len(sample)} items)

Classify each as: **real miss** (Aegis should detect), **duplicate**
(KICS/Checkov double-counts), **unsupported** (feature Aegis lacks),
**false positive** (competitor wrong), or **scope mismatch**
(outside Aegis's claimed coverage).

{chr(10).join(sample_lines)}

## Group D — uncomparable (first 20)

{top(groups['D'], 20)}
"""
    with open(out_path, "w") as f:
        f.write(md)
    return out_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--aegis", required=True)
    ap.add_argument("--kics", required=True)
    ap.add_argument("--checkov", required=True)
    ap.add_argument("--rules", default="aegis_rules.json",
                    help="Aegis rule dump (id/title/severity)")
    ap.add_argument("--mapping", default="rule_mapping.json")
    ap.add_argument("--out", default="differential_report.md")
    ap.add_argument("--sample", type=int, default=30)
    args = ap.parse_args()

    aegis = parse_aegis(args.aegis)
    kics = parse_kics(args.kics)
    checkov = parse_checkov(args.checkov)
    print(f"parsed: aegis={len(aegis)} kics={len(kics)} checkov={len(checkov)}",
          file=sys.stderr)

    with open(args.rules) as f:
        aegis_rules = json.load(f)
    mapping = load_mapping(args.mapping)

    groups = group_findings(aegis, kics, checkov, mapping, aegis_rules)
    write_report(groups, args.out, args.sample)
    print(f"groups: " + ", ".join(f"{k}={len(v)}" for k, v in groups.items()))
    print(f"report: {args.out}")


if __name__ == "__main__":
    main()
