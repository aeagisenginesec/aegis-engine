#!/usr/bin/env python3
"""Item 6b round 2: ARM (azuredeploy.json + $schema marker) and PlanJSON (*.plan.json) probes."""
import os, subprocess, time, json, shutil, sys

BIN = "/tmp/aegis-item6b/aegis"
BASE = "/tmp/aegis-item6b/probes2"
TIMEOUT = 30
ARM_HEAD = b'{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", "contentVersion": "1.0.0.0", "resources": ['

def run_case(name, files):
    d = os.path.join(BASE, name)
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    for fname, data in files.items():
        with open(os.path.join(d, fname), "wb") as f:
            f.write(data)
    t0 = time.time()
    try:
        cp = subprocess.run([BIN, "scan", d, "--format=json"], capture_output=True, timeout=TIMEOUT)
        wall = time.time() - t0
        out = cp.stdout.decode("utf-8", "replace")
        findings = diags = "?"
        try:
            doc = json.loads(out)
            findings = len(doc.get("findings", []))
            diags = [x["message"] for x in doc.get("diagnostics", [])]
            comp = doc.get("scan_completeness", {})
            fmt = ""
            for fl in comp.get("files", []):
                fmt += fl.get("format", "?") + ":" + fl.get("status", "?") + " "
        except Exception as e:
            fmt = f"unparsable: {e}"
        print(f"{name}\texit={cp.returncode}\twall={wall:.2f}\tfindings={findings}\tfiles={fmt}\tdiags={diags}", flush=True)
    except subprocess.TimeoutExpired:
        print(f"{name}\tTIMEOUT>{TIMEOUT}s", flush=True)

def json_deep(n):
    return b'[' + b'[' * n + b'1' + b']' * n + b']'

cases = []
# ARM: deep nesting inside resources[0].properties, huge string, null bytes, invalid utf8
cases.append(("arm2-deep-10k", {"azuredeploy.json": ARM_HEAD + b'{"type":"Microsoft.Storage/storageAccounts","apiVersion":"2023-01-01","name":"x","properties":{"a":' + json_deep(10000) + b'}}]}'}))
cases.append(("arm2-deep-100k", {"azuredeploy.json": ARM_HEAD + b'{"type":"Microsoft.Storage/storageAccounts","apiVersion":"2023-01-01","name":"x","properties":{"a":' + json_deep(100000) + b'}}]}'}))
cases.append(("arm2-huge-string", {"azuredeploy.json": ARM_HEAD + b'{"type":"Microsoft.Storage/storageAccounts","apiVersion":"2023-01-01","name":"' + b'A' * (5 << 20) + b'","properties":{"allowBlobPublicAccess":true}}]}'}))
cases.append(("arm2-null-bytes", {"azuredeploy.json": ARM_HEAD + b'{"type":"Microsoft.Storage/storageAccounts\x00","apiVersion":"2023-01-01","name":"x"}]}'}))
cases.append(("arm2-invalid-utf8", {"azuredeploy.json": ARM_HEAD + b'{"type":"Microsoft.Storage/storageAccounts","apiVersion":"2023-01-01","name":"\xff\xfe"}]}'}))
cases.append(("arm2-truncated", {"azuredeploy.json": ARM_HEAD + b'{"type":"Microsoft.Storage/storageAccounts"'}))
cases.append(("arm2-vuln-clean", {"azuredeploy.json": ARM_HEAD + b'{"type":"Microsoft.Storage/storageAccounts","apiVersion":"2023-01-01","name":"x","location":"eastus","sku":{"name":"Standard_LRS"},"kind":"StorageV2","properties":{"allowBlobPublicAccess":true}}]}'}))
# PlanJSON: deep nesting, huge string, null bytes, invalid utf8, truncated
cases.append(("plan2-deep-10k", {"x.plan.json": b'{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","name":"b","values":{"bucket":' + json_deep(10000) + b'}}]}}}'}))
cases.append(("plan2-deep-100k", {"x.plan.json": b'{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","name":"b","values":{"bucket":' + json_deep(100000) + b'}}]}}}'}))
cases.append(("plan2-huge-string", {"x.plan.json": b'{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","name":"b","values":{"bucket":"' + b'A' * (5 << 20) + b'"}}]}}}'}))
cases.append(("plan2-null-bytes", {"x.plan.json": b'{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.b\x00","type":"aws_s3_bucket","name":"b","values":{}}]}}}'}))
cases.append(("plan2-invalid-utf8", {"x.plan.json": b'{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","name":"b","values":{"bucket":"\xff\xfe"}}]}}}'}))
cases.append(("plan2-truncated", {"x.plan.json": b'{"format_version":"1.0","planned_values":{"root_module":{"resources":['}))
cases.append(("plan2-vuln-clean", {"x.plan.json": b'{"format_version":"1.0","planned_values":{"root_module":{"resources":[{"address":"aws_s3_bucket.b","type":"aws_s3_bucket","name":"b","values":{"bucket":"x"}}]}}}'}))

for name, files in cases:
    run_case(name, files)
