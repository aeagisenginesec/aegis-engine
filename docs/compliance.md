# Compliance mapping, posture reporting & waivers

Aegis maps its rules to the controls they genuinely enforce, reports a
per-framework pass/fail posture for a scan, and governs accepted-risk
suppressions as **waivers with expiry** — a waiver that lapses brings its
finding back, loudly.

## Frameworks

Ten frameworks are mapped (943 of 1,140 rules carry at least one control
reference; the rest are deliberately unmapped — build hygiene, availability
tuning and similar checks that no control genuinely covers):

| Framework | Source |
|---|---|
| CIS-AWS-1.5 | CIS Amazon Web Services Foundations Benchmark v1.5 |
| CIS-Azure-2.1 | CIS Microsoft Azure Foundations Benchmark v2.1 |
| CIS-GCP-1.3 | CIS Google Cloud Platform Foundation Benchmark v1.3 |
| CIS-Kubernetes-1.8 | CIS Kubernetes Benchmark v1.8 |
| CIS-Docker-1.6 | CIS Docker Benchmark v1.6 |
| NIST-800-53 | NIST SP 800-53 Rev. 5 |
| PCI-DSS-4.0 | PCI Data Security Standard v4.0 |
| ISO-27001-2022 | ISO/IEC 27001:2022 Annex A |
| SOC2 | AICPA SOC 2 Trust Services Criteria (CC series) |
| HIPAA | HIPAA Administrative Simplification, 45 CFR Part 164 |

Mapping doctrine (enforced in review, stated in the source): a rule is
mapped only where the control genuinely applies. ISO 27001, SOC 2 and
HIPAA references are crosswalked from the rule's NIST 800-53 anchors via
the standard published correspondences, and HIPAA references appear only
for concepts inside its safeguards (access control, audit controls,
integrity, authentication, transmission security, encryption, backup).
CIS controls are cited only where the benchmark control is certain —
precision over coverage.

## Posture reporting

`--compliance` accepts one framework, a comma-separated list, or `all`:

```bash
# Single framework: findings are filtered to it (original behaviour),
# plus a per-control pass/fail summary.
aegis scan . --compliance=NIST-800-53

# Several frameworks (or all): every finding is kept, enriched with all
# its mapped controls, and one posture summary is reported per framework.
aegis scan . --compliance=NIST-800-53,PCI-DSS-4.0,ISO-27001-2022
aegis scan . --compliance=all --format=json   # -> compliance_summaries[]
```

A control **fails** when at least one finding maps to it and **passes**
otherwise; the summary reports controls evaluated / passing / failing and
the list of failed controls, in text and JSON output alike.

## Attestation report (HTML)

```bash
aegis scan . --format=html > attestation.html
```

renders a standalone attestation page: a single self-contained HTML file
(inline CSS, print-friendly) with the per-framework posture table and
the full findings table with per-finding compliance references. The
output is deterministic for a given scan — re-running on the same tree
reproduces it — and secrets are redacted exactly as in the JSON report.
When `--compliance` is not given, the attestation covers all ten
frameworks.

## Waivers: baselines with expiry

A baseline entry is a waiver when it carries governance metadata
(see [BASELINES.md](BASELINES.md) for the file format):

```json
{ "rule_id": "AEGIS-AWS-001", "resource": "aws_s3_bucket.legacy",
  "attribute": "server_side_encryption_configuration",
  "reason": "migration tracked in TICKET-123", "owner": "sec-team",
  "expires": "2027-01-01T00:00:00Z" }
```

Author waivers from the CLI:

```bash
aegis scan . --baseline-out=.aegis/baseline.json \
  --waiver-reason="accepted risk: legacy bucket" \
  --waiver-owner="sec-team" \
  --waiver-expires=2027-01-01T00:00:00Z
```

(every entry gets the same terms; hand-edit the JSON to give individual
entries their own). Governance rules:

- **A live waiver suppresses silently.** That is its job.
- **An expired waiver stops suppressing.** The finding returns to the
  results, and the scan prints a warning per lapsed waiver naming the
  expiry date, rule, resource and owner — a lapse is never silent, so
  accepted risk cannot quietly become permanent.
- **An unparseable `expires` value is flagged on every load.** The entry
  keeps suppressing (fail-open on content), but the warning makes the
  defect impossible to miss: as written, that waiver never expires.
- Entries without `expires` do not lapse. Use them only for permanent,
  structural acceptances — and expect reviewers to ask why.

## Honest scope

Posture is computed from the rules Aegis can evaluate statically on the
scanned tree. A passing control means *no mapped finding fired in this
tree* — it is evidence for an audit, not the audit itself. Frameworks
that require live-cloud evidence (drift, runtime configuration, IAM
activity) are out of scope for a static scanner and are not claimed.
