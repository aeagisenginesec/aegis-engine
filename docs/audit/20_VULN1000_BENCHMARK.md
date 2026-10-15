# 20 — vuln-1000 benchmark: Aegis 2.0.0 on a 1000-file vulnerable fixture

Date: 2026-10-15. Engine: Aegis 2.0.0 (commit 4582801, redesigned CLI output).
Fixture: `~/workspace/vuln-1000/` — 1000 deliberately-vulnerable IaC files,
17,911 lines, generated deterministically by `~/workspace/vuln-1000-gen.py`
(seed=1000; fixture files byte-identical across regenerations).
Generator lives outside the fixture root so regeneration cannot delete it.
All credentials are fake placeholders. Never apply against real accounts.

## Fixture composition

| Area | Files |
|---|---|
| terraform/aws/ | 250 |
| terraform/azure/ | 200 |
| terraform/gcp/ | 150 |
| docker/ (Dockerfiles) | 100 |
| k8s/ (manifests) | 150 |
| cloudformation/ | 100 |
| compose/ | 50 |
| **Total** | **1000** (+ README) |

Each file contains 1–4 vulnerable resources drawn from template pools with
seeded variation. One fixture-naming lesson: compose files must match the
adapter's filename patterns (`docker-compose.<name>.yml`); the initial
`docker-compose-<name>.yml` (dash) variant was discovered-but-not-parsed,
which the scan summary surfaced honestly as 50 skipped files.

## Results (3 runs, `--format=json`)

| Run | Findings | Critical | High | Medium | Low | Files | Resources | Wall time | Peak RSS |
|---|---|---|---|---|---|---|---|---|---|
| 1 (cold) | 9,719 | 503 | 2,839 | 3,567 | 2,810 | 1000/1000 | 1,558 | 0.65s | 89.6 MB |
| 2 | 9,719 | 503 | 2,839 | 3,567 | 2,810 | 1000/1000 | 1,558 | 0.47s | 81.6 MB |
| 3 | 9,719 | 503 | 2,839 | 3,567 | 2,810 | 1000/1000 | 1,558 | 0.46s | 84.2 MB |

- **Determinism: byte-identical finding sets across all 3 runs**
  (rule_id, file, line, title tuples).
- **231 distinct rules fired** out of the 1,153-rule registry.
- Exit code 1 on all runs (findings present), as designed.

## Findings by format

| Format | Findings |
|---|---|
| Terraform | 5,728 |
| CloudFormation | 1,384 |
| Kubernetes | 1,383 |
| Docker | 968 |
| Compose | 256 |

## Top rules

106× each: AEGIS-K8S-006 (no resource limits), -012 (latest tag), -014/-015
(no liveness/readiness probes), -028 (writable root fs), -029 (no seccomp),
-030 (capabilities), -031 (no NetworkPolicy), -032 (no digest pin);
105× AEGIS-AWS-339 (hardcoded credentials); 100× each AEGIS-DOCKER-001/-002.

## Critical spotlight (503 total)

| Count | Rule |
|---|---|
| 71 | AEGIS-K8S-001 Container running as privileged |
| 67 | AEGIS-AWS-006 IAM policy allows all actions on all resources |
| 67 | AEGIS-AWS-501 IAM privilege escalation (create policy + attach) |
| 67 | AEGIS-AWS-502 IAM privilege escalation via iam:PassRole |
| 51 | AEGIS-AWS-104 Public S3 exfiltration path |
| 36 | AEGIS-GCP-001 GCS bucket publicly readable via IAM |
| 32 | AEGIS-GCP-293 Secret in instance metadata startup script |
| 30 | AEGIS-GCP-040 Cloud SQL open to the internet |

## Honest notes

- Raw finding count measures **volume on a deliberately-vulnerable fixture**,
  not precision. Precision is measured separately (R4 benchmark: F1 0.950).
- K8s hygiene rules (probes, limits, digests) dominate the raw count; the
  critical list is where the breach material lives.
- Memory was system-constrained during the run (7 GB box, ~0 free);
  peak RSS stayed under 90 MB regardless.
- The fixture is ~2.4× the vuln-500 file count; scan time scaled
  sub-linearly (0.47s vs 0.28s) — parsing dominates, not rule count.
