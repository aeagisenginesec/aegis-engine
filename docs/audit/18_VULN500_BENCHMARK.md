# Aegis v2.0.0 — vuln-500 Large-Fixture Benchmark

Date: 2026-10-14. Binary: `aegis-v2.0.0-linux-amd64` (v2.0.0, build 2026-10-14,
commit e589088). Fixture: `~/workspace/vuln-500/` (see its README).

## 1. Fixture composition

A deliberately vulnerable multi-format IaC project. All credential-looking
strings are fake placeholders (`fakepassword123`, `fakeEXAMPLEsecretkey123`).
Never apply to real cloud accounts.

| Directory         | Format               | Files | Lines |
|-------------------|----------------------|------:|------:|
| `terraform/`      | Terraform (AWS/Azure/GCP) | 3 | 5,117 |
| `docker/`         | Dockerfiles          |    24 |   240 |
| `k8s/`            | Kubernetes manifests |     1 | 1,279 |
| `cloudformation/` | CloudFormation YAML  |    24 |   672 |
| `compose/`        | docker-compose       |    16 |   208 |
| **Total**         |                      | **68** | **7,516** |

Breadth: public S3/GCS buckets, open security groups / firewalls / NSGs,
public unencrypted RDS/Cloud SQL, EC2 with public IPs + secrets in user_data,
wildcard IAM policies, unencrypted EBS, public Azure SQL/Storage, open Key
Vaults, Debian 10 images, hardcoded secrets, root/privileged containers,
hostNetwork pods, `latest` images, missing resource limits.

## 2. Aegis results

**4,522 findings, 145 distinct rules, 0 diagnostics.** Byte-identical across
all 5 runs (determinism verified).

| Severity | Findings |
|----------|---------:|
| critical |      288 |
| high     |    1,416 |
| medium   |    1,680 |
| low      |    1,138 |

Top firing rules: AEGIS-AWS-604 ×120, AEGIS-AWS-002/012/104/443/445/601 ×72
each, AEGIS-AWS-004 ×56, AEGIS-AWS-007/008 ×48 each.

## 3. Performance — 5 runs

| Run | Findings | Wall time | Peak RSS |
|----:|---------:|----------:|---------:|
| 1 | 4,522 | 0.2027 s | 54.8 MB |
| 2 | 4,522 | 0.1961 s | 51.9 MB |
| 3 | 4,522 | 0.2645 s | 60.9 MB |
| 4 | 4,522 | 0.2562 s | 48.3 MB |
| 5 | 4,522 | 0.1786 s | 49.7 MB |
| **mean** | — | **0.22 s** | **53.1 MB** |
| min / max | — | 0.18 / 0.26 s | 48.3 / 60.9 MB |

Wall time measured with `date +%s%N` around the process; peak RSS from
`/usr/bin/time -v` (Maximum resident set size). No meaningful cold/warm
difference: run 1 (0.20 s) was not the slowest; spread is system noise.

**Density: 60.2 findings per 100 lines scanned.**

### Per-format breakdown (each subdirectory scanned separately)

| Format | Files | Lines | Findings | Wall time | Peak RSS |
|--------|------:|------:|---------:|----------:|---------:|
| terraform | 3 | 5,117 | 2,946 | 0.1125 s | 35.8 MB |
| docker | 24 | 240 | 386 | 0.0226 s | 18.8 MB |
| k8s | 1 | 1,279 | 562 | 0.0358 s | 18.7 MB |
| cloudformation | 24 | 672 | 554 | 0.0310 s | 20.7 MB |
| compose | 16 | 208 | 82 | 0.0171 s | 15.9 MB |

Note: per-format findings sum to 4,530 vs 4,522 whole-tree. The delta (+8)
is AEGIS-AWS-567/569 (Security Hub / Detective not enabled), which are
module-level `CheckAll` rules evaluated per scan scope — they fire when
`terraform/` is scanned alone but not in the whole-tree scan. Scope-dependent
behavior, not non-determinism (same input → identical output held 5/5).

## 4. Run quirks discovered (honesty notes)

1. **Compose filename routing.** Files named `docker-compose-0.yml` (dash)
   are claimed by the Kubernetes manifests adapter and skipped as
   "unrecognized document" — zero findings, only a diagnostic. The compose
   adapter only matches `docker-compose.yml`, `docker-compose.<name>.yml`,
   `compose.yml`, and `*.compose.yml`. Renamed to `docker-compose.<i>.yml`;
   compose then produced 82 findings. Users with dash-named compose files
   get a diagnostic, not silent zero — acceptable, but the naming rule is
   easy to trip over.
2. **CloudFormation multi-document YAML.** Only the first `---` document of
   a multi-doc YAML file is analyzed; remaining stacks are silently dropped
   (no diagnostic). Worked around with one file per stack (554 findings vs
   25 before). Single-document templates — the normal case — are unaffected.
3. **Raw counts are not precision evidence.** 4,522 is a volume/speed
   number. It says nothing about false positives; the fixture is
   deliberately saturated, so density (60/100 lines) is not representative
   of real codebases.

## 5. Competitor comparison

Not run. `trivy`, `checkov`, and `kics` are not installed in this
environment, and the task instructions forbade new installs. No competitor
numbers are claimed.

## 6. Plain-language summary

Aegis v2.0.0 scanned a 7,516-line, 5-format deliberately vulnerable project
and reported **4,522 findings from 145 distinct rules in about 0.22 seconds
using about 53 MB of RAM** — roughly 60 findings per 100 lines, with
byte-identical output on every run. The per-format timings show parsing
dominates: the 5,117-line Terraform set took 0.11 s while the smaller
formats each finished in under 0.04 s. Two adapter edge cases surfaced
(compose filename matching, CloudFormation multi-doc files); both are
documented above, neither affects normal single-format scans.
