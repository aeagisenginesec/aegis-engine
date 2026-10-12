# Differential Benchmark Triage

Compares Aegis vs KICS vs Checkov findings on the same corpus, grouping by
(normalized resource, canonical rule).

## Usage

```bash
# Collect outputs
./aegis scan <dir> --format=json > aegis.json
kics scan -p <dir> -q <queries> -o kics-out  # results in kics-out/results.json
checkov -d <dir> --framework terraform -o json > checkov.json

# Run triage
python3 triage.py --aegis aegis.json --kics kics-out/results.json \
    --checkov checkov.json --out differential_report.md
```

## Groups

| Group | Meaning |
|---|---|
| A | Detected by all three (or Aegis + at least one other) |
| B | Only Aegis detects |
| C | Only KICS and/or Checkov detect — **investigation target** |
| D | Cannot be compared reliably (unmapped rules, scope mismatches, parse issues) |

## Files

- `triage.py` — the triage tool
- `rule_mapping.json` — explicit KICS/Checkov → Aegis rule mappings, plus
  `scope_mismatch` list and `known_gaps`
- `aegis_rules.json` — all 698 Aegis rules (id/title/severity), for fuzzy matching
- `kics_query_index.json` — all 762 KICS Terraform queries (id/name/severity/category)
- `differential_report.md` — vuln-200 triage output (Group C sample for manual labeling)
- `differential_vuln200.md`, `differential_terragoat.md` — per-corpus reports
- `group_c_distinct.json` — deduplicated Group C issue types
- `CLASSIFICATION.md` — manual classification of Group C findings

## Key Findings (2026-10-12)

Most Group C "misses" are **competitor false positives**, not Aegis gaps:
- Checkov/KICS flag absent attributes as vulnerable even when the AWS
  provider default is secure (KMS policy, Redshift `publicly_accessible`,
  SQS SSE-SQS, EC2 public IP)
- KICS applies IAM logic to IoT policies (which don't use Principal)
- S3 operational hygiene (replication, notifications) flagged as security

See `CLASSIFICATION.md` for the full analysis.

## Normalization

- **Resources:** module prefixes stripped, `${...}` resolved, array indices
  removed, trailing attributes trimmed, KICS bucket-name vs label handled
  via fuzzy prefix matching
- **Rules:** explicit mappings first, then fuzzy title matching (Jaccard ≥ 0.30
  with synonym canonicalization), requiring provider AND resource-type
  compatibility
- **Cross-attribution:** KICS attributes policy findings to the referenced
  resource; Aegis to the policy. Aliases merge these.
