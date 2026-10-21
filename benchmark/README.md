# ⚠️ Benchmark data — intentionally vulnerable

Everything under `benchmark/` is **test data for the scanner**, not
deployable infrastructure: labeled corpora, comparison fixtures
(TerraGoat and friends), the rigorous benchmark sets, and the R5
held-out blind set used to measure Aegis's recall and precision.

**Do not deploy any of it.** The misconfigurations are the point —
they are how scanner accuracy is proven. These trees are excluded
from every code scanner wired into this repo (see `.semgrepignore`,
`.snyk`, `.github/codeql/codeql-config.yml`, and the SonarCloud
exclusions in `.github/workflows/sonar.yml`) precisely so that
findings reported on the *product* stay meaningful.
