# ⚠️ Demo stack — intentionally vulnerable

The Terraform in `demo/` contains deliberate misconfigurations used
in the README walkthrough: you scan it with Aegis and watch the
findings land. **Do not deploy it** — that is the whole point of the
exercise.

It is excluded from the repo's code scanners (see `.semgrepignore`,
`.snyk`, `.github/codeql/codeql-config.yml`, and the SonarCloud
exclusions in `.github/workflows/sonar.yml`); scanning it is
Aegis's job, and it does it in the self-gate on every push.
