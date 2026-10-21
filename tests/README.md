# ⚠️ Test fixtures — intentionally vulnerable

The stacks and files under `tests/` (especially `tests/demos/` and
`tests/fixtures/`) are **inputs for Aegis's own test suites**:
deliberately misconfigured Terraform, parser edge cases, and demo
stacks the documentation walks you through scanning.

**Do not deploy any of it.** These trees are excluded from the
repo's code scanners (see `.semgrepignore`, `.snyk`,
`.github/codeql/codeql-config.yml`, and the SonarCloud exclusions in
`.github/workflows/sonar.yml`) so product findings stay meaningful.
