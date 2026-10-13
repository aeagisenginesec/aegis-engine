#!/usr/bin/env python3
"""Validate the c-group corpus: YAML/JSON parse, Bicep brace balance, dir/file counts."""
import json
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("pyyaml not available")
    sys.exit(2)

BASE = os.path.expanduser("~/workspace/aegis-engine/docs/audit/raw/final-eval/corpus")
errors = []
yaml_ok = json_ok = bicep_ok = 0
file_count = 0

# Tolerate CloudFormation intrinsic-function tags (!Ref, !Sub, ...)
def _cfn_ctor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)

yaml.SafeLoader.add_multi_constructor("!", _cfn_ctor)

def strip_bicep_comments_and_strings(text):
    # remove // comments and /* */ blocks, then string literals
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    lines = []
    for line in text.splitlines():
        # naive // strip (bicep has no // inside strings in our files except URLs; safe enough)
        idx = line.find("//")
        if idx != -1:
            line = line[:idx]
        lines.append(line)
    text = "\n".join(lines)
    text = re.sub(r"'''(.*?)'''", "", text, flags=re.S)
    text = re.sub(r"'([^'\\\\]|\\\\.)*'", "", text)
    return text

for i in range(1, 71):
    pid = f"c{i:03d}"
    d = os.path.join(BASE, pid)
    if not os.path.isdir(d):
        errors.append(f"{pid}: MISSING DIRECTORY")
        continue
    files = []
    for root, _, fns in os.walk(d):
        for f in sorted(fns):
            files.append(os.path.relpath(os.path.join(root, f), d))
    if not (1 <= len(files) <= 3):
        errors.append(f"{pid}: expected 1-3 files, found {len(files)}")
    for f in files:
        p = os.path.join(d, f)
        file_count += 1
        with open(p) as fh:
            content = fh.read()
        if not content.strip():
            errors.append(f"{pid}/{f}: EMPTY FILE")
            continue
        if f.endswith((".yaml", ".yml")):
            try:
                yaml.safe_load(content)
                yaml_ok += 1
            except Exception as e:
                errors.append(f"{pid}/{f}: YAML parse error: {e}")
        elif f.endswith(".json"):
            try:
                json.loads(content)
                json_ok += 1
            except Exception as e:
                errors.append(f"{pid}/{f}: JSON parse error: {e}")
        elif f.endswith(".bicep"):
            stripped = strip_bicep_comments_and_strings(content)
            if stripped.count("{") != stripped.count("}"):
                errors.append(f"{pid}/{f}: brace imbalance {{={stripped.count('{')} }}={stripped.count('}')}")
            elif stripped.count("[") != stripped.count("]"):
                errors.append(f"{pid}/{f}: bracket imbalance")
            elif stripped.count("(") != stripped.count(")"):
                errors.append(f"{pid}/{f}: paren imbalance")
            else:
                bicep_ok += 1
        else:
            errors.append(f"{pid}/{f}: unexpected extension")

print(f"files checked: {file_count} (yaml_ok={yaml_ok} json_ok={json_ok} bicep_ok={bicep_ok})")
if errors:
    print(f"ERRORS ({len(errors)}):")
    for e in errors:
        print("  " + e)
    sys.exit(1)
print("ALL VALIDATION CHECKS PASSED")
