# ⚠️ Evaluation corpora — intentionally vulnerable

`docs/audit/` holds the accuracy campaign's working data: the R3/R4
ground-truth corpora, the R5 blind evaluation inputs, raw scanner
outputs, and the adjudication records behind the published numbers
(see `26_AEGIS_FINAL_STATE.md`).

The Terraform and scripts here are **evidence, not product code** —
much of it is deliberately vulnerable because that is what was being
measured. **Do not deploy any of it.** These trees are excluded from
the repo's code scanners (see `.semgrepignore`, `.snyk`,
`.github/codeql/codeql-config.yml`, and the SonarCloud exclusions in
`.github/workflows/sonar.yml`) so product findings stay meaningful.
