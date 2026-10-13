#!/usr/bin/env python3
"""Item 6b adversarial probes: run the CLI against hostile inputs, one subprocess per case.
Each case gets its own dir + timeout so a crash/hang is isolated and attributable.
Prints a TSV-ish summary: case, exit, wall_s, rss_mb, findings, diagnostics, tail."""
import os, subprocess, sys, time, resource, json, shutil

BIN = "/tmp/aegis-item6b/aegis"
BASE = "/tmp/aegis-item6b/probes"
TIMEOUT = 30

def run_case(name, files):
    d = os.path.join(BASE, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for fname, data in files.items():
        p = os.path.join(d, fname)
        os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(fname) else None
        with open(p, "wb") as f:
            f.write(data)
    t0 = time.time()
    try:
        cp = subprocess.run([BIN, "scan", d, "--format=json"], capture_output=True, timeout=TIMEOUT)
        wall = time.time() - t0
        out = cp.stdout.decode("utf-8", "replace")
        err = cp.stderr.decode("utf-8", "replace")
        findings = resources = diags = "?"
        try:
            doc = json.loads(out)
            findings = len(doc.get("findings", []))
            resources = doc.get("scan_completeness", {}).get("files_discovered", "?")
            diags = len(doc.get("diagnostics", []))
        except Exception:
            pass
        tail = (err.strip().splitlines() or [""])[-1][:160]
        print(f"{name}\texit={cp.returncode}\twall={wall:.2f}\tfindings={findings}\tdiags={diags}\tstderr_tail={tail!r}", flush=True)
        return cp.returncode, wall
    except subprocess.TimeoutExpired:
        print(f"{name}\tTIMEOUT>{TIMEOUT}s", flush=True)
        return "TIMEOUT", TIMEOUT

def tf_deep_blocks(n):
    return (b'resource "aws_s3_bucket" "b" {\n' + b'x = ' + b'{' * n + b'1' + b'}' * n + b'\n}\n')

def tf_deep_calls(n):
    # concat(concat(... "x" ...))
    return b'resource "aws_s3_bucket" "b" {\n bucket = ' + b'concat(' * n + b'"x"' + b')' * n + b'\n}\n'

def yaml_deep(n, fname_kind="seq"):
    # nested sequences: "- - - ... x"
    return ("a: " + "[" * n + "1" + "]" * n + "\n").encode()

def json_deep(n):
    return (b'{"a": ' + b'[' * n + b'1' + b']' * n + b'}')

def bicep_deep(n):
    return b"var x = " + b"[" * n + b"1" + b"]" * n + b"\n"

cases = []
# --- Terraform HCL ---
cases.append(("tf-deep-blocks-5k", {"main.tf": tf_deep_blocks(5000)}))
cases.append(("tf-deep-blocks-50k", {"main.tf": tf_deep_blocks(50000)}))
cases.append(("tf-deep-calls-5k", {"main.tf": tf_deep_calls(5000)}))
cases.append(("tf-deep-calls-50k", {"main.tf": tf_deep_calls(50000)}))
cases.append(("tf-huge-string-5m", {"main.tf": b'resource "aws_s3_bucket" "b" {\n bucket = "' + b'A' * (5 << 20) + b'"\n}\n'}))
cases.append(("tf-null-bytes", {"main.tf": b'resource "aws_s3_bucket" "b" {\x00 bucket = "x" }\n'}))
cases.append(("tf-invalid-utf8", {"main.tf": b'resource "aws_s3_bucket" "b" {\n bucket = "\xff\xfe\x00\x01"\n}\n'}))
cases.append(("tf-unclosed-string", {"main.tf": b'resource "aws_s3_bucket" "b" {\n bucket = "never closed\n}\n'}))
cases.append(("tf-brackets-1m", {"main.tf": b'[' * (1 << 20)}))
cases.append(("tf-locals-diamond", {"main.tf": _diamond() if False else b'locals { a0 = "xxxxxxxx" }\n' + b''.join(b'locals { a%d = "${local.a%d}${local.a%d}" }\n' % (i, i-1, i-1) for i in range(1, 25)) + b'resource "aws_s3_bucket" "b" {\n bucket = local.a24\n}\n'}))
# cyclic modules: a -> b -> a
cases.append(("tf-module-cycle", {
    "main.tf": b'module "a" { source = "./a" }\n',
    "a/main.tf": b'module "b" { source = "../b" }\nresource "aws_s3_bucket" "in_a" { bucket = "x" }\n',
    "b/main.tf": b'module "a" { source = "../a" }\nresource "aws_s3_bucket" "in_b" { bucket = "x" }\n',
}))
cases.append(("tf-module-self", {
    "main.tf": b'module "self" { source = "./self" }\n',
    "self/main.tf": b'module "self" { source = "./self" }\nresource "aws_s3_bucket" "s" { bucket = "x" }\n',
}))
cases.append(("tf-module-deep-chain", {
    **{"main.tf": b'module "m0" { source = "./m0" }\n'},
    **{f"m{i}/main.tf": (f'module "m{i+1}" {{ source = "../m{i+1}" }}\n'.encode() if i < 60 else b'resource "aws_s3_bucket" "deep" { bucket = "x" }\n') for i in range(61)},
}))
# --- Plan JSON ---
cases.append(("plan-deep-10k", {"plan.json": json_deep(10000)}))
cases.append(("plan-deep-100k", {"plan.json": json_deep(100000)}))
cases.append(("plan-huge-string", {"plan.json": b'{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","name":"b","values":{"bucket":"' + b'A' * (5 << 20) + b'"}}]}}}'}))
cases.append(("plan-null-bytes", {"plan.json": b'{"a": "\x00\x01\x02"}'}))
cases.append(("plan-invalid-utf8", {"plan.json": b'{"a": "\xff\xfe"}'}))
cases.append(("plan-truncated", {"plan.json": b'{"format_version":"1.0","planned_values":{"root_module":{"resources":['}))
# --- CloudFormation ---
cases.append(("cfn-deep-10k", {"t.yaml": yaml_deep(10000)}))
cases.append(("cfn-deep-100k", {"t.yaml": yaml_deep(100000)}))
cases.append(("cfn-huge-string", {"t.yaml": b'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: "' + b'A' * (5 << 20) + b'"\n'}))
cases.append(("cfn-null-bytes", {"t.yaml": b'Resources:\n  B:\n    Type: AWS::S3::Bucket\x00\n'}))
cases.append(("cfn-invalid-utf8", {"t.yaml": b'Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: "\xff\xfe"\n'}))
cases.append(("cfn-dup-keys-2k", {"t.yaml": b'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n' + b''.join(b'      K%d: v\n' % i for i in range(2000)) + b'      K0: dup\n'}))
# --- ARM ---
cases.append(("arm-deep-10k", {"t.json": json_deep(10000)}))
cases.append(("arm-deep-100k", {"t.json": json_deep(100000)}))
cases.append(("arm-huge-string", {"t.json": b'{"$schema":"x","contentVersion":"1.0.0.0","resources":[{"type":"Microsoft.Storage/storageAccounts","apiVersion":"2023-01-01","name":"' + b'A' * (5 << 20) + b'","properties":{"allowBlobPublicAccess":true}}]}'}))
cases.append(("arm-null-bytes", {"t.json": b'{"resources": [{"type": "x\x00y"}]}'}))
cases.append(("arm-invalid-utf8", {"t.json": b'{"resources": [{"type": "\xff\xfe"}]}'}))
# --- Bicep ---
cases.append(("bicep-deep-10k", {"main.bicep": bicep_deep(10000)}))
cases.append(("bicep-deep-100k", {"main.bicep": bicep_deep(100000)}))
cases.append(("bicep-deep-ternary-5k", {"main.bicep": b"var x = " + b"true ? " * 5000 + b"1" + b" : 2" * 5000 + b"\n"}))
cases.append(("bicep-var-chain-5k", {"main.bicep": b"var v0 = 'x'\n" + b"".join(b"var v%d = v%d\n" % (i, i-1) for i in range(1, 5001)) + b"resource st 'Microsoft.Storage/storageAccounts@2023-01-01' = { name: v5000 location: 'eastus' }\n"}))
cases.append(("bicep-huge-string", {"main.bicep": b"var x = '" + b"A" * (5 << 20) + b"'\n"}))
cases.append(("bicep-null-bytes", {"main.bicep": b"var x = 'a\x00b'\n"}))
cases.append(("bicep-invalid-utf8", {"main.bicep": b"var x = '\xff\xfe'\n"}))
# --- Pulumi ---
cases.append(("pulumi-deep-10k", {"Pulumi.yaml": b"name: t\nruntime: yaml\nresources:\n  b:\n    type: aws:s3:Bucket\n    properties:\n      bucket: " + b"[" * 10000 + b"1" + b"]" * 10000 + b"\n"}))
cases.append(("pulumi-deep-100k", {"Pulumi.yaml": b"name: t\nruntime: yaml\nresources:\n  b:\n    type: aws:s3:Bucket\n    properties:\n      bucket: " + b"[" * 100000 + b"1" + b"]" * 100000 + b"\n"}))
cases.append(("pulumi-null-bytes", {"Pulumi.yaml": b"name: t\x00\nruntime: yaml\nresources: {}\n"}))
cases.append(("pulumi-invalid-utf8", {"Pulumi.yaml": b"name: \xff\xfe\nruntime: yaml\nresources: {}\n"}))
# --- Dockerfile ---
cases.append(("docker-huge-line-5m", {"Dockerfile": b"FROM ubuntu:latest\nRUN echo " + b"A" * (5 << 20) + b"\nUSER root\n"}))
cases.append(("docker-many-lines-200k", {"Dockerfile": b"FROM ubuntu:latest\n" + b"RUN echo hi\n" * 200000 + b"USER root\n"}))
cases.append(("docker-continuation-100k", {"Dockerfile": b"FROM ubuntu:latest\nRUN echo " + b"\\\n" * 100000 + b"done\n"}))
cases.append(("docker-null-bytes", {"Dockerfile": b"FROM ubuntu:latest\nUSER \x00root\n"}))
cases.append(("docker-invalid-utf8", {"Dockerfile": b"FROM ubuntu:latest\n# \xff\xfe comment\nUSER root\n"}))
# --- Compose ---
cases.append(("compose-deep-10k", {"compose.yaml": b"services:\n  web:\n    image: nginx\n    environment:\n      X: " + b"[" * 10000 + b"1" + b"]" * 10000 + b"\n"}))
cases.append(("compose-deep-100k", {"compose.yaml": b"services:\n  web:\n    image: nginx\n    environment:\n      X: " + b"[" * 100000 + b"1" + b"]" * 100000 + b"\n"}))
cases.append(("compose-nonmapping-service", {"compose.yaml": b"services:\n  web: justastring\n  db:\n    image: postgres\n    privileged: true\n"}))
cases.append(("compose-null-bytes", {"compose.yaml": b"services:\n  web:\n    image: nginx\x00\n"}))
cases.append(("compose-invalid-utf8", {"compose.yaml": b"services:\n  web:\n    image: \xff\xfe\n"}))
# --- K8s manifests ---
cases.append(("k8s-deep-10k", {"m.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: deep\ndata:\n  x: " + b"[" * 10000 + b"1" + b"]" * 10000 + b"\n"}))
cases.append(("k8s-deep-100k", {"m.yaml": b"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: deep\ndata:\n  x: " + b"[" * 100000 + b"1" + b"]" * 100000 + b"\n"}))
cases.append(("k8s-many-docs-10k", {"m.yaml": (b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n---\n" * 10000)}))
cases.append(("k8s-null-bytes", {"m.yaml": b"apiVersion: v1\x00\nkind: Pod\n"}))
cases.append(("k8s-invalid-utf8", {"m.yaml": b"apiVersion: v1\nkind: Pod\nmetadata:\n  name: \xff\xfe\n"}))
cases.append(("k8s-unknown-kind", {"m.yaml": b"apiVersion: v1\nkind: TotallyMadeUp\nmetadata:\n  name: x\nspec:\n  privileged: true\n"}))
cases.append(("k8s-no-kind", {"m.yaml": b"apiVersion: v1\nmetadata:\n  name: x\n"}))

if __name__ == "__main__":
    only = sys.argv[1:] or None
    for name, files in cases:
        if only and name not in only:
            continue
        run_case(name, files)
