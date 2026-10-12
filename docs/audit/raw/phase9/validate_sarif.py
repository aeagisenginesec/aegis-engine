#!/usr/bin/env python3
"""Validate an Aegis SARIF file against the official SARIF 2.1.0 JSON schema
plus the structural rules GitHub code scanning enforces.

Usage: python3 validate_sarif.py <file.sarif> [--schema sarif-2.1.0.json]

Exit 0: valid and acceptable to GitHub code scanning.
Exit 1: schema violations or missing GitHub-required structure.
Exit 2: usage/file error.
"""
import json
import os
import sys

SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"  # mirror of OASIS spec


def main():
    if len(sys.argv) < 2:
        print("usage: validate_sarif.py <file.sarif> [--schema path]", file=sys.stderr)
        return 2
    path = sys.argv[1]
    schema_path = None
    if "--schema" in sys.argv:
        schema_path = sys.argv[sys.argv.index("--schema") + 1]
    if not os.path.exists(path):
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 2
    with open(path) as f:
        try:
            doc = json.load(f)
        except json.JSONDecodeError as e:
            print(f"SCHEMA-FAIL: not valid JSON: {e}")
            return 1

    errors = []

    # --- Official SARIF 2.1.0 schema validation ---
    if schema_path and os.path.exists(schema_path):
        try:
            import jsonschema
            with open(schema_path) as f:
                schema = json.load(f)
            jsonschema.validate(doc, schema)
            print("PASS: conforms to SARIF 2.1.0 JSON schema (jsonschema)")
        except ImportError:
            print("WARN: jsonschema not installed; schema check skipped")
        except Exception as e:
            errors.append(f"schema validation failed: {e}")
    else:
        print("WARN: schema file not provided/found; schema check skipped")

    # --- GitHub code-scanning structural requirements ---
    # (https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning)
    def check(cond, msg):
        if not cond:
            errors.append(msg)

    check(doc.get("version") == "2.1.0",
          f"version must be '2.1.0', got {doc.get('version')!r}")
    runs = doc.get("runs")
    check(isinstance(runs, list) and len(runs) >= 1, "runs must be a non-empty array")
    if isinstance(runs, list):
        for i, run in enumerate(runs):
            tool = run.get("tool", {})
            driver = tool.get("driver", {})
            check(bool(driver.get("name")), f"runs[{i}].tool.driver.name is required")
            rules = {r.get("id") for r in driver.get("rules", []) if isinstance(r, dict)}
            results = run.get("results", [])
            check(isinstance(results, list), f"runs[{i}].results must be an array")
            if isinstance(results, list):
                check(len(results) <= 5000,
                      f"runs[{i}] has {len(results)} results; GitHub caps uploads at 5000")
                for j, res in enumerate(results):
                    rid = res.get("ruleId")
                    check(bool(rid), f"runs[{i}].results[{j}].ruleId is required")
                    if rid and rules:
                        check(rid in rules,
                              f"runs[{i}].results[{j}].ruleId {rid!r} has no matching "
                              f"tool.driver.rules[] entry (GitHub rejects dangling ruleIds)")
                    locs = res.get("locations")
                    check(isinstance(locs, list) and len(locs) >= 1,
                          f"runs[{i}].results[{j}] needs >=1 location for code scanning")
                    for loc in (locs or []):
                        pl = loc.get("physicalLocation", {})
                        uri = pl.get("artifactLocation", {}).get("uri")
                        check(bool(uri),
                              f"runs[{i}].results[{j}] location missing "
                              f"physicalLocation.artifactLocation.uri")

    size = os.path.getsize(path)
    check(size < 10 * 1024 * 1024,
          f"SARIF file is {size} bytes; GitHub code-scanning upload limit is 10 MB")

    if errors:
        print("GITHUB-ACCEPTANCE: FAIL")
        for e in errors:
            print(f"  - {e}")
        return 1
    n_results = sum(len(r.get("results", [])) for r in (runs or []))
    print(f"GITHUB-ACCEPTANCE: PASS ({n_results} results, {size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
