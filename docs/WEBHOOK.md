# SIEM / SOAR webhook output

`aegis scan --webhook <url>` POSTs the scan result to an HTTPS endpoint
after the scan completes, for SIEM/SOAR ingestion. This closes SOC item
#17 from the v2.3.0 blueprint (deferred: "JSON/SARIF piping is the
supported path today; `aegis serve` exists for SOAR integration") with a
native push path. Piping `--format=json` and `aegis serve` remain
supported; the webhook is the third, push-based option.

## Quick start

```sh
# Token from the environment (preferred — never on the command line in
# shared shell history); the flag wins when both are set.
export AEGIS_WEBHOOK_SECRET='...'

aegis scan ./infra \
  --webhook https://siem.example.com/hooks/aegis \
  --webhook-secret "$AEGIS_WEBHOOK_SECRET"
```

A generic receiver in Python (stdlib only) that accepts the delivery:

```python
# siem_receiver.py — minimal webhook sink for testing. Do NOT use in
# production without authentication and TLS termination in front of it.
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        event = json.loads(body)
        print(f"aegis {event['aegis_version']}: "
              f"{event['summary']['findings']} findings "
              f"on {event['target']}")
        for f in event["findings"]:
            print(f"  {f['severity']:8} {f['rule_id']} {f['file']}:{f['line']} {f['resource']}")
        self.send_response(200)
        self.end_headers()

HTTPServer(("127.0.0.1", 8443), Handler).serve_forever()
```

```sh
# Loopback receiver: plain HTTP needs the explicit opt-in.
python3 siem_receiver.py &
aegis scan ./infra --webhook http://127.0.0.1:8443/hook --webhook-allow-http
```

## Payload

The payload is **byte-identical in shape to `aegis scan --format=json`**:
the same versioned envelope (`aegis_version`, `target`, `summary`,
`findings`, `diagnostics`, `scan_completeness`, `compliance_summaries`),
produced by the same code path (`report.WriteJSON`). A SIEM parser
written against `--format=json` output works unchanged against webhook
deliveries. The request carries `Content-Type: application/json` and
`User-Agent: aegis/<version>`.

```json
{
  "aegis_version": "2.3.0",
  "target": "./infra",
  "summary": {"resources": 12, "findings": 3, "critical": 1, "high": 1, "medium": 1, "low": 0},
  "findings": [
    {
      "rule_id": "AEGIS-AWS-002",
      "severity": "high",
      "title": "S3 bucket allows public ACLs",
      "resource": "aws_s3_bucket.data",
      "file": "main.tf",
      "line": 4,
      "evidence": "acl = public-read",
      "remediation": "..."
    }
  ],
  "diagnostics": [],
  "scan_completeness": {"files_discovered": 3, "files_parsed": 3}
}
```

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--webhook <url>` | — | HTTPS endpoint to POST the JSON report to |
| `--webhook-secret <token>` | `AEGIS_WEBHOOK_SECRET` | Bearer token (`Authorization: Bearer <token>`). Prefer the env var; the flag wins when both are set |
| `--webhook-header "Name: value"` | — | Extra header (repeatable). `Authorization` is rejected here — use `--webhook-secret` |
| `--webhook-timeout <seconds>` | 10 | Per-attempt timeout (connect + send + read). A slow endpoint can never hang a scan |
| `--webhook-attempts <n>` | 3 | Total attempts, 1–10. 5xx/429 and transport errors retry with exponential backoff (500ms, 1s, 2s, …); 4xx is not retried |
| `--webhook-allow-http` | off | Allow a plain-`http://` URL. Loopback/lab receivers only |
| `--webhook-dry-run` | off | Print what would be sent (endpoint, header names only, payload size, redacted preview) without sending |
| `--webhook-fail-on-error` | off | Exit 2 when delivery fails (see below) |

## Security

- **HTTPS only.** A plain-`http://` URL is refused unless
  `--webhook-allow-http` is given. Findings contain file paths,
  resource names and rule IDs — over HTTP that crosses the wire in
  cleartext. The opt-out exists for loopback/lab receivers only.
- **Secrets are redacted twice.** Rules 534–539 never put a secret
  value in a finding, and the payload is rendered through
  `report.WriteJSON`, which replaces secret-looking evidence values
  with `[REDACTED]` — the same path as the CLI JSON report. A test
  (`TestPayloadRedactsSecrets`, plus the end-to-end
  `TestScanWebhookSecretRedactedEndToEnd` with a live AEGIS-AWS-538
  fixture) proves a hardcoded secret never appears in the payload.
- **The token never appears in output.** It is never logged, never
  included in an error message, and dry-run shows header names only
  (`Authorization: Bearer ***`). URLs with embedded userinfo
  (`https://token@host/...`) are rejected at validation; error
  messages show the endpoint host/path only, never the query string.
- **Validation fails fast.** The URL, timeout, attempts and headers
  are validated before the scan starts (exit 2), so a bad endpoint
  costs no scan time.
- **Delivery failure never loses the local result.** The local report
  is written first; a failed delivery is a stderr warning and the
  exit code still reflects the scan findings (0 clean / 1 findings /
  2 usage error). Pass `--webhook-fail-on-error` to make a failed
  delivery exit 2 instead — for CI jobs where a silent undelivered
  report is worse than a failed build.

## Exit codes

| Situation | Exit code |
|---|---|
| Scan clean, delivery OK | 0 |
| Findings, delivery OK | 1 |
| Findings, delivery failed (default) | 1 (warning on stderr) |
| Scan clean, delivery failed (default) | 0 (warning on stderr) |
| Delivery failed with `--webhook-fail-on-error` | 2 |
| Bad webhook URL / flags | 2 (before scanning) |

## What is deliberately NOT in this version

- **No SARIF webhook payload.** The JSON envelope is the delivery
  format; SIEMs consume JSON natively, and SARIF stays a file/pipe
  format (`--format=sarif`). A `--webhook-format=sarif` switch is a
  small follow-up if a consumer asks for it.
- **No HMAC request signing.** Bearer auth plus HTTPS covers the
  documented receivers; HMAC adds a shared-secret provisioning story
  that belongs with the receiver's spec, not guessed here.
- **No persistent queue / store-and-forward.** A failed delivery is
  reported, not retried later: the local report (or `--format=json`
  piped to a file) is the durable record, and re-running the scan
  re-delivers. A queue would need durable state and an operator story.
- **No `serve`-mode webhook.** `aegis serve` stays pull-based; the
  webhook is a `scan`-time push. Wiring delivery into the API is a
  separate design decision (per-request endpoints, authz).
