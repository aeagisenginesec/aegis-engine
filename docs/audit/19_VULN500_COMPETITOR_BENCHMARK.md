# vuln-500 Competitor Benchmark — Aegis vs Snyk vs Checkov vs KICS

Date: 2026-10-14. All four tools attempted; three produced measurements.

## 1. Methodology

**Fixture:** `~/workspace/vuln-500/` — 69 files, 7,516 lines: Terraform (AWS/Azure/GCP),
Dockerfiles (24), Kubernetes manifests, CloudFormation templates (24),
docker-compose files (16). All credential-looking strings are fake placeholders;
the fixture README states it must never be applied to real cloud accounts.
Full composition in `docs/audit/18_VULN500_BENCHMARK.md`.

**System:** 2 vCPU (AMD EPYC 9D25), 7.7 GB RAM, Linux 7.0.0-39-generic x86_64,
Go 1.25.4. The box was memory-pressured during testing (only ~300–700 MB free).

**Measurement:** identical for every tool — wall-clock time and peak RSS from
`/usr/bin/time -v` (Maximum resident set size), total findings counted from
machine-readable output (JSON). One clean run per tool; no retries, no tuning,
no cherry-picking. Timeouts capped at 30 minutes per run (none hit).

**Commands:**
- Aegis v2.0.0: `aegis-v2.0.0-linux-amd64 scan ~/workspace/vuln-500 --format=json`
- Snyk 1.1307.4: `snyk iac test ~/workspace/vuln-500/ --json` (then without `--json`)
- Checkov 3.3.26 (venv): `checkov -d ~/workspace/vuln-500/ -o json`
- KICS 2.1.20: `kics scan -p ~/workspace/vuln-500 --report-formats json -o <dir>`
  (run from `~/workspace/kics/` so `./assets/queries` resolves; 1,810 queries)

## 2. Results

| Tool | Version | Findings | Wall time | Peak RSS | Notes |
|---|---|---|---|---|---|
| **Aegis** | v2.0.0 | **4,522** (288 crit / 1,416 high / 1,680 med / 1,138 low; 145 distinct rules) | **0.28 s** | **49 MB** | exit 1 (findings present); byte-identical across 5 runs |
| **Checkov** | 3.3.26 | **3,770** failed checks (no severity in JSON output) | **16.57 s** | **392 MB** | 4,592 passed, 0 skipped, 0 parsing errors; compose framework checks absent (§3) |
| **KICS** | 2.1.20 | **5,116** (112 crit / 2,427 high / 1,552 med / 665 low / 360 info) | **135.78 s** | **195 MB** | exit 60; 119 queries hit of 1,837; silently skipped all 24 Dockerfiles (§3) |
| **Snyk** | 1.1307.4 | **n/a — could not run** | 28.3 s (failed) | 251 MB (failed run) | monthly quota exhausted (200 private tests); rules bundle download failed (SNYK-CLI-0012) |

**Measured ratios (from the numbers above):**
- Aegis vs Checkov: **~59× faster** (16.57 / 0.28), **~8× less memory** (392 / 49)
- Aegis vs KICS: **~485× faster** (135.78 / 0.28), **~4× less memory** (195 / 49)
- Finding counts: Aegis 4,522 vs Checkov 3,770 vs KICS 5,116 — see §5,
  counts are not precision evidence and the tools did not all see the same files.

## 3. Per-format notes and run quirks

**Aegis:** terraform 2,946 / 0.11 s · k8s 562 / 0.036 s · cloudformation 554 /
0.031 s · docker 386 / 0.023 s · compose 82 / 0.017 s. All 68 IaC files scanned.

**Checkov** failed checks by framework: terraform 2,408 · kubernetes 840 ·
cloudformation 384 · dockerfile 96 · secrets 42. Quirk: the 16 compose files
(`docker-compose-<n>.yml` naming) produced **no** `docker_compose` framework
results — only 16 secrets-framework hits reference compose files. Compose
misconfiguration checks did not run on them.

**KICS** findings by platform: Terraform 3,108 · CloudFormation 720 ·
Kubernetes 1,000 · Common 144 · DockerCompose 144. Quirk: KICS scanned only
**44 of 68** IaC files — all **24 Dockerfiles were silently skipped** (zero
Dockerfile-platform queries, zero docker file paths in results, 0 parsing
errors reported). Its 5,116 findings exclude the entire docker format.

**Snyk:** no per-format data — the scan never started (§4).

## 4. Snyk failure detail (exact behavior)

Attempt 1 (`--json`): exit 2 after 28.34 s —
`FailedToDownloadRulesError: Failed to download policies`.
Attempt 2 (plain): printed `You have reached your monthly limit of 200 private
tests for your redaxacto org` and `ERROR IAC failure (SNYK-CLI-0012): We were
unable to download the security rules, please ensure the network can access
https://downloads.snyk.io`. No scan executed; no quota consumed by these
attempts (both failed before any test ran). No further attempts made — the
quota wall is a hard stop, not a transient error.

## 5. Honesty section (read first)

- **Raw finding counts are volume evidence, not precision evidence.** A higher
  count does not mean "better" — it can mean broader rule coverage, but it can
  also mean noisier rules. Precision/recall require independently labeled
  ground truth, which does not exist for this fixture. Do not cite these
  numbers as accuracy claims.
- **The tools did not all see the same files.** KICS silently skipped 24
  Dockerfiles; Checkov ran no compose-framework checks. Cross-tool finding
  counts are therefore not directly comparable even as volume measures.
- **Different tools count different things.** Aegis counts per-finding with
  severity; Checkov counts failed checks with no severity in JSON output and
  additionally runs a secrets framework (42 hits) outside Aegis's IaC-misconfig
  scope; KICS counts per-query-file hits including 360 INFO.
- **Snyk is absent, not slow.** Its quota was already exhausted before this
  benchmark began; nothing about Snyk's speed or coverage can be concluded.
- **Environment:** a 2-vCPU, memory-pressured sandbox favors lean binaries.
  Results describe this workload on this box, not universal performance.

## 6. KICS acquisition note

KICS v2 (current v2.2.0) publishes **no prebuilt Linux binary** — documented
install paths are Docker (unavailable in this sandbox) or build-from-source.
The binary used here (`~/workspace/bin/kics`, v2.1.20) was already present on
this machine from prior work; a fresh source build was started but abandoned
once the existing binary was found. It requires `./assets/queries` relative to
the working directory (`~/workspace/kics/assets/queries`, 1,810 queries).

## 7. Plain-language summary

On a 7,516-line, five-format vulnerable project, Aegis v2.0.0 produced
4,522 findings in 0.28 seconds using 49 MB of RAM — about 59× faster and
8× leaner than Checkov (16.57 s / 392 MB), and about 485× faster and 4× leaner
than KICS (135.78 s / 195 MB) on the same fixture. KICS reported the highest
raw count (5,116) but silently skipped all 24 Dockerfiles; Checkov skipped
compose-framework checks. Snyk could not participate (quota exhausted). These
numbers speak to speed and resource efficiency on this workload; they say
nothing about which tool is more accurate.
