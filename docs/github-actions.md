# Aegis in GitHub Actions

Aegis ships as a GitHub Action so it can be the **principal IaC
scanner** in a pipeline — the role teams usually give Snyk IaC or
Trivy's config scanning — with findings as native GitHub code
scanning annotations and a severity gate on the job.

```yaml
jobs:
  aegis:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # for the SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: aeagisenginesec/aegis-engine@v2
        with:
          path: ./infra
          fail-on: high
```

The Action downloads the pinned Aegis release binary for the
runner's OS/architecture, verifies it against the release's
published `SHA256SUMS.txt`, runs the scan, and (by default) uploads
the SARIF report to code scanning. The same binary, the same
findings, as the CLI — Aegis output is deterministic, so a scan in
CI reproduces locally byte-for-byte.

## Inputs

| Input | Default | Purpose |
|---|---|---|
| `path` | `.` | Directory to scan. |
| `version` | `v2.2.0` | Aegis release to run. Pinned per release; the download is SHA-256 verified. |
| `fail-on` | `high` | Lowest severity that fails the job: `critical`, `high`, `medium`, `low`, or `none` (report-only). |
| `baseline` | *(empty)* | Path to a baseline file. Baselined findings are suppressed and never fail the gate. |
| `upload-sarif` | `true` | Upload SARIF to code scanning. Needs `security-events: write` on the job. |
| `args` | *(empty)* | Extra arguments passed verbatim to `aegis scan`. |

## Outputs

| Output | Meaning |
|---|---|
| `sarif-file` | Absolute path of the SARIF report on the runner. |
| `findings` | Number of findings in the report, after baseline suppression. |

## Adopting Aegis as the principal scanner

The low-risk path, in three phases:

### Phase 1 — Shadow (report-only)

Run Aegis next to your current scanner for a week or two. No gate:
compare findings on real pull requests before trusting the swap.

```yaml
      - uses: aeagisenginesec/aegis-engine@v2
        with:
          path: ./infra
          fail-on: none
```

### Phase 2 — Baseline the debt, gate the new

Record today's findings as a baseline, commit it, and gate only on
what's new:

```bash
aegis scan ./infra --baseline-out=aegis-baseline.json || true
git add aegis-baseline.json && git commit -m "aegis: baseline existing findings"
```

```yaml
      - uses: aeagisenginesec/aegis-engine@v2
        with:
          path: ./infra
          fail-on: high
          baseline: aegis-baseline.json
```

Refresh the baseline deliberately (after a cleanup sprint, or when
accepting a new known finding) — it is a policy decision, and it
belongs in a commit someone reviewed.

### Phase 3 — Cutover

Make the Aegis job a required status check and remove the old
scanner's IaC steps. Keep whatever your old tool did that Aegis
does not: Aegis is a misconfiguration scanner — it replaces Snyk
IaC and Trivy *config* scanning, not dependency/container CVE
scanning (Trivy, Snyk Open Source) or dedicated secret scanners.

## Pinning

`@v2` tracks the latest v2 Action. For maximum supply-chain
rigidity, pin the full commit SHA of the release you reviewed —
Dependabot's `github-actions` package ecosystem keeps either form
current, exactly as this repository does for its own workflows.

## What runs where

The Action is a composite action: it runs on Linux, macOS and
Windows runners (x64 and ARM64) and needs nothing preinstalled —
`curl`, `jq` and `sha256sum` ship with the GitHub-hosted images.
Self-hosted runners need those three tools on PATH.

## Equivalence with the CLI

Every input maps to a documented CLI invocation:

```bash
aegis scan <path> --format=sarif [--fail-on=<severity>] [--baseline=<file>] [args...]
```

If a CI result ever surprises you, run that line locally on the
same tree: the findings will match exactly.
