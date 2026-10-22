# Aegis Baselines

Baselines suppress known findings so CI only reports *new* issues. A baseline
is a JSON file listing finding fingerprints to ignore.

## Quick start

```bash
# Capture current findings as a baseline
aegis scan ./infra --baseline-out=baseline.json

# Later scans suppress baselined findings
aegis scan ./infra --baseline=baseline.json
```

## Fingerprints

Each finding is identified by a stable fingerprint:

| Field | Description |
|-------|-------------|
| `rule_id` | e.g. `AEGIS-AWS-001` |
| `resource` | e.g. `aws_s3_bucket.data` |
| `attribute` | e.g. `server_side_encryption_configuration` |

Fingerprints deliberately exclude line numbers, values, and descriptions —
reformatting code or editing comments does not resurrect baselined findings.
Moving a resource or changing the flagged attribute creates a new fingerprint
(which is correct: it may be a different issue).

## v2 format (with metadata)

```json
{
  "version": 2,
  "entries": [
    {
      "rule_id": "AEGIS-AWS-001",
      "resource": "aws_s3_bucket.logs",
      "attribute": "server_side_encryption_configuration",
      "reason": "Legacy bucket; migration tracked in TICKET-123",
      "owner": "sec-team",
      "expires": "2027-01-01T00:00:00Z"
    }
  ]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `reason` | No | Why this finding is accepted (ticket link, justification) |
| `owner` | No | Team or person accountable for the exception |
| `expires` | No | RFC3339 date — after this, the entry stops suppressing |

Expired entries are dropped on load with no error: the finding reappears in
the next scan, forcing re-review.

## v1 format (legacy, still supported)

```json
{
  "version": 1,
  "fingerprints": [
    {
      "rule_id": "AEGIS-AWS-001",
      "resource": "aws_s3_bucket.logs",
      "attribute": "server_side_encryption_configuration"
    }
  ]
}
```

v1 files load unchanged. Plain `--baseline-out` writes v1 (flat list, no
metadata). To write v2 waiver entries from the CLI, add
`--waiver-reason` / `--waiver-owner` / `--waiver-expires` to the
`--baseline-out` run — every entry is stamped with those terms; hand-edit
the JSON afterwards for per-entry terms.

Expiry is **loud**: when an entry's `expires` date has passed, the entry
stops suppressing and the scan warns on stderr for each lapsed waiver
(date, rule, resource, owner — "finding reinstated"). An entry whose
`expires` cannot be parsed keeps suppressing but is warned about on every
load — a typo must never mint a permanent silent waiver. See
[compliance.md](compliance.md) for the governance model.

## Inline suppressions

For one-off exceptions tied to the code itself, use a comment instead of a
baseline file:

```hcl
resource "aws_s3_bucket" "logs" {
  # aegis:skip=AEGIS-AWS-001
  bucket = "logs"
}
```

`# aegis:skip=RULE-ID` (or comma-separated IDs, or `all`) suppresses only
that resource+rule pair. Prefer baselines with reasons for anything that
needs review or expiry.
