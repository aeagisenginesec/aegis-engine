# 14 — Remediation Safety + API Security Audit (Item 5)

**Mission:** Top-tier validation, item 5 of 6
**Date:** 2026-10-13
**Branch:** `mission/top-tier-validation`
**Binary under test:** `go build` of branch HEAD → `/tmp/aegis-item5`
(`aegis 1.0.0`, `doctor`: 1,151 rules loaded)
**Prior work reused, not redone:** Phase 4 Workstream 4 safety audit
(2026-10-11, quoted in `internal/remediation/fixers.go` header).
This item re-verifies those guarantees live and extends to the full
20-project matrix + the API threat model.

## Verdicts

| Area | Verdict |
|---|---|
| `aegis fix` safety (no corruption, no new vulns, no unsafe writes) | **PASS** |
| `aegis fix` coverage (how many findings are auto-fixable) | **NARROW — 8 of 1,151 rules** (by design, see §1.7) |
| API authentication / authorization | **PASS** |
| API input validation / resource exhaustion | **PASS** |
| API coverage parity with CLI | **FAIL — DEFECT-1 (HIGH)**: CFN loses secret rules, ARM loses everything (§2.7) |

No corruption, no unsafe auto-fix, no API crash, no secret leak, and no
authentication bypass were found. One real High-severity API defect was
found: silent coverage loss on content-sniffed formats.

## 1. `aegis fix` safety

### 1.1 Method

Corpus: the 20 vulnerable projects from the parent session
(`/tmp/vuln20`, rebuilt from the recorded fixture definitions after
`/tmp` was wiped): Terraform (AWS/Azure/GCP/EKS/Lambda/multi-cloud),
CloudFormation, ARM, Bicep, Pulumi (TypeScript), Dockerfile, Compose, K8s.
Plus targeted probes: comments/formatting, reference values, malformed
files, `--force`, `--rule` filter, empty dir, non-Terraform formats.

Per project: copy → `scan` (before) → `fix --apply` → `scan` (after) →
compare finding sets, file hashes, and diffs. A fix is **safe** iff:
no file is corrupted, no unrelated finding disappears, no new finding
appears, and only the intended property changes.

### 1.2 Matrix result

| Project | Before | Removed | Kept | New | Files changed |
|---|---|---|---|---|---|
| 01-tf-aws-s3-iam | 16 | 1 | 15 | 0 | 1 |
| 02-tf-aws-rds-ec2 | 17 | 0 | 17 | 0 | 0 |
| 03-tf-azure-sql-kv | 26 | 0 | 26 | 0 | 0 |
| 04-tf-gcp-sql-gcs | 24 | 0 | 24 | 0 | 0 |
| 05-tf-eks-k8s | 3 | 0 | 3 | 0 | 0 |
| 06-tf-lambda-sqs | 8 | 0 | 8 | 0 | 0 |
| 07-cfn-s3-rds | 21 | 0 | 21 | 0 | 0 |
| 08-cfn-ec2-sg | 6 | 0 | 6 | 0 | 0 |
| 09-arm-storage-sql | 35 | 0 | 35 | 0 | 0 |
| 10-arm-nsg-vm | 4 | 0 | 4 | 0 | 0 |
| 11-bicep-storage | 24 | 0 | 24 | 0 | 0 |
| 12-pulumi-aws (TS) | 0 | 0 | 0 | 0 | 0 |
| 13-pulumi-azure (TS) | 0 | 0 | 0 | 0 | 0 |
| 14-docker-root | 11 | 0 | 11 | 0 | 0 |
| 15-docker-secrets | 12 | 0 | 11* | 0 | 0 |
| 16-compose-priv | 6 | 0 | 6 | 0 | 0 |
| 17-compose-hostnet | 6 | 0 | 6 | 0 | 0 |
| 18-k8s-priv-pod | 10 | 0 | 10 | 0 | 0 |
| 19-k8s-rbac-nodeport | 7 | 0 | 7 | 0 | 0 |
| 20-tf-multicloud | 53 | 0 | 53 | 0 | 0 |

\* Project 15: finding count 12 → 11 with set-based kept=11, removed=0:
two findings shared one (rule, resource, attribute) key (DOCKER-003
fires twice on the same stage); the set comparison masks the duplicate.
No finding was lost; one duplicate-key finding left the set. Counts in
this table are set-based except where noted.

**Zero new findings introduced by any applied patch. Zero files
corrupted. Zero unrelated findings lost.**

Baseline note: counts here (e.g. 02: 17, 07: 21) differ slightly from
the parent session's scan (02: 22, 07: 23) because this binary includes
the uncommitted Item 6 parser fixes, which changed detection on some
fixtures. The matrix above is self-consistent (before/after on the
same binary).

### 1.3 Why so few fixes applied: only 8 fixers exist

The fixer registry (`internal/remediation/remediation.go`,
`DefaultFixers`) contains exactly 8 fixers, all Terraform-only,
all AWS:

| Rule | Fix |
|---|---|
| AEGIS-AWS-001 | Insert `server_side_encryption_configuration` (AES256) |
| AEGIS-AWS-002 | `acl = "private"` (known public values only) |
| AEGIS-AWS-007 | `storage_encrypted = true` (RDS) |
| AEGIS-AWS-008 | `deletion_protection = true` (RDS) |
| AEGIS-AWS-009 | `encrypted = true` (EBS) |
| AEGIS-AWS-010 | `enable_log_file_validation = true` (CloudTrail) |
| AEGIS-AWS-011 | `publicly_accessible = false` (RDS) |
| AEGIS-AWS-012 | Insert `versioning { enabled = true }` (S3) |

Deliberately NOT fixed (per the fixer header): 003 (policy rewrite),
004/005 (CIDR legitimacy is a decision), 006 (least-privilege scoping),
101/102/103/104 (attack paths need redesign). Everything else —
all Azure/GCP/K8s/Docker/Compose/CFN/ARM/Bicep/Pulumi rules — has no
fixer. CFN/Dockerfile/K8s probes confirmed: 0 patches proposed,
0 writes, no crash.

The single applied patch in the matrix was AEGIS-AWS-012 (versioning)
in project 01. This is a coverage limitation, not a safety failure —
but any "auto-remediation" claim must be scoped to these 8 rules.

### 1.4 Validation gate: correctly refused the ACL patch (with a caveat)

Dry-run on project 01 proposes 2 patches: AWS-002 (ACL → private) and
AWS-012 (versioning). Under `--apply`, only AWS-012 is written.
AWS-002 is refused: `would fix: true, new findings: 2, apply: skipped
(did not validate cleanly)`.

Root cause of the "2 new findings": AWS-001 (SSE) and AWS-206 (PAB)
deliberately suppress themselves on intentionally-public buckets
(`3da23be`: a bucket with a public ACL is treated as intentionally
public). Flipping the ACL to private lifts the suppression, so the two
genuine findings (the bucket really lacks SSE and PAB) appear in the
post-patch scan. The gate compares (rule, resource, attribute) keys,
so suppression-lift reveals count as "new findings" and the patch is
refused.

Assessment: the gate is **fail-closed and correct to refuse** — the
patch does not meet the "fixes cleanly with no new findings" contract.
But the behaviour is surprising: a correct, safe patch is refused
because the scan's own suppression logic re-keys findings. Users must
re-run `fix` after each round (round 2 then fixes AWS-001, etc.).
Documented here as a known gate limitation, not a defect. A future
improvement would be to compare finding *issues* (rule+resource)
rather than (rule, resource, attribute) keys, or to exempt
suppression-lift reveals — neither was changed in this audit.

### 1.5 One patch per resource per run — converges

AWS-007 and AWS-008 both insert before the same resource's closing
brace. When both are proposed in one run, the second is skipped
(`overlaps … patch`), and applied on the next run. Verified:
round 1 applied 007 (+012 on the bucket), round 2 applied 008,
round 3 stable (only the refused 001 patch re-proposed). No loop,
no lost fix, convergence in ≤3 rounds on the tested files.

### 1.6 Idempotency, formatting, references, refusals — all PASS

| Test | Result |
|---|---|
| Idempotency (3 consecutive `--apply` runs) | Stable: run 1 applies versioning (16→15 findings), runs 2–3 identical (15 findings, only the refused ACL patch re-proposed) |
| Comments preserved | All comment forms survive: top-of-file, inline trailing, inner-resource, tag comments. Only target lines change. |
| Formatting | No reformatting of adjacent lines. **Cosmetic nits:** inserted lines don't align `=` columns with neighbours; diff header shows `--- a//tmp/…` (double slash). Neither corrupts anything. |
| Reference values | `storage_encrypted = var.encrypt` is **NOT** rewritten (literal-only guard). Only the absent-attribute (008) and literal-false (009) patches applied. The variable binding is preserved. |
| `--force` on IAM | No-op in practice: no IAM/networking fixer exists. The wildcard IAM policy is byte-identical after `fix --apply --force`. Warning printed as documented. |
| Malformed file | Broken `.tf` left byte-identical; fix proceeds on the good file. Exit 0. |
| `--rule` filter | Only the requested rule's patch proposed. |
| Empty dir | 0 findings, 0 patches, exit 0. |
| Non-Terraform formats | CFN / Dockerfile / K8s: 0 patches, 0 writes, no crash. |

### 1.7 Fix verdict

**PASS (safe), coverage NARROW.** The validation gate, overlap rule,
literal-only guard, reference guard, and fail-closed refusals all
behave as designed. No applied patch introduced a finding, broke a
deployment semantic, or touched an unrelated line. Any claim about
auto-remediation must state the 8-rule scope.

## 2. API security audit (`aegis serve`)

### 2.1 Threat model

`aegis serve` exposes `POST /v1/scan` (arbitrary IaC content in,
findings out) and `GET /v1/health`. Default bind is loopback
`127.0.0.1:8734`; `--auth-token` / `AEGIS_SERVE_TOKEN` enables
Bearer auth. Attackers: unauthenticated local users (no token),
remote clients (if bound non-loopback), and malicious scan content
(parser DoS, secret exfiltration via responses, disk access via
crafted paths).

### 2.2 Probe results (21 probes, all live)

| # | Probe | Expected | Observed |
|---|---|---|---|
| 1 | GET /v1/health | 200 | 200 `{"status":"ok"}` |
| 2 | POST /v1/scan, no auth (token set) | 401 | 401 `unauthorized` |
| 3 | POST /v1/scan, wrong token | 401 | 401 |
| 4 | POST /v1/scan, valid token + TF | 200 + findings | 200, findings returned |
| 5 | Malformed JSON | 400 | 400 `invalid JSON body` |
| 6 | Trailing garbage after JSON | 400 | 400 `invalid JSON body (trailing data)` |
| 7 | GET /v1/scan | 405 | 405 |
| 8 | POST /v1/health | 405 | 405 |
| 9 | Unknown route /v1/admin | 404 | 404 |
| 10 | Unknown ruleset | 400 | 400 `unknown ruleset` |
| 11 | Empty body | 400 | 400 |
| 12 | `"files": null` | 200 empty | 200, 0 findings (acceptable) |
| 13 | 1001 files | 400 | 400 `too many files (max 1000)` |
| 14 | 33 MiB body | 413 | 413 `request body exceeds 32 MiB` |
| 15 | Path traversal `../../etc/passwd` (no .tf) | No disk read | 0 resources; warning `no adapter handles …` only. Path treated as label. |
| 16 | Secret in evidence (DB password) | Redacted | Secret absent from response |
| 17 | Traversal with `.tf` extension | Parse CONTENT, not disk | 1 resource, 6 findings from supplied content; no disk read |
| 18 | 20 parallel small scans | All succeed, server alive | 20× 200, health 200 after |
| 19 | Server alive after abuse | 200 | 200 |
| 20 | No-token mode on loopback | Works, no auth warning | 200; log `listening on 127.0.0.1:…` (no warning — correct) |
| 21 | Non-loopback, no token | Warning logged | `WARNING: listening on non-loopback … with NO authentication` |
| 22 | 30 parallel heavy scans (200 files each, cap 16) | Fail-fast 503s, no crash | 16× 200, 14× 503 `server busy`; server alive |
| 23 | Token in logs | Never logged | 0 occurrences in serve logs |

Implementation controls verified by reading `cmd/aegis/serve.go`:
constant-time token comparison (`subtle.ConstantTimeCompare`),
concurrency cap (16, fail-fast, never queue), 32 MiB body cap
(`MaxBytesReader`), 1000-file cap, strict JSON (trailing data
rejected), 60 s handler timeout + 70 s read timeout + 10 s header
timeout, diagnostic truncation (2048 chars), panic-text sanitisation
in parse errors, secret redaction on secret-named evidence attributes.

### 2.3 What did NOT leak

- The token never appears in logs or error responses.
- Submitted secrets never appear in responses: DB password
  (`master_password`) redacted; CFN `MasterUserPassword` findings
  (339/850) carry `[REDACTED]` evidence in CLI output; the Lambda
  env-secret probe produced no secret-echoing finding.
- Error responses are generic JSON (`invalid JSON body`,
  `unauthorized`); no stack traces, no internal paths.

### 2.4 Non-issues (checked, not defects)

- `GET /v1/health` is unauthenticated by design: it returns only
  `status` + `version`, no sensitive data.
- No per-client rate limiting (only the global 16-scan concurrency
  cap). A single client can retry 503s in a loop. Acceptable for a
  loopback-default service; operators binding non-loopback should
  front it with a reverse proxy. Rated Low, no action required.
- `"files": null` → 200 with empty results (lenient, harmless).

### 2.5 Parser-safety note (in-tree test)

The tree carries `internal/adapter/manifests/item5_yaml_test.go`
(untracked, from prior validation work): YAML duplicate-key /
anchor-alias inputs fail fast with exactly one bounded error
diagnostic (regression for the old quadratic-error-list OOM path).
It passes. It is filed under "item5" but belongs to parser safety;
it is committed with this item's work and counted in the scorecard
under parser safety, not remediation.

### 2.6 DEFECT-1 (HIGH): API silently loses findings on content-sniffed formats

**Severity: High.** The API returns 200 with an incomplete finding
set and — for CFN — no warning at all.

**Reproduction (same bytes, same binary):**

| Case | CLI findings | API findings | Missing |
|---|---|---|---|
| CFN `template.yaml` (RDS, hardcoded + weak password) | 14 | 11 | AWS-339, AWS-710, AWS-850 |
| ARM `template.json` (storage + SQL) | 35 | **0** | all 35 |

**Root cause.** `cloudformation.Handles(path)` and `arm.Handles(path)`
do not decide by name/extension alone — they sniff file *content
from disk* (`looksLikeCFN` reads the file for
`AWSTemplateFormatVersion`; `looksLikeARM` reads it for
`deploymenttemplate.json`). In `scanFilesInMemory`
(`cmd/aegis/serve.go`), the file exists only in memory, so the disk
read fails, both adapters decline, and the file falls through to the
`manifests` adapter:

- CFN: manifests parses the YAML generically, producing a resource
  with *unmapped* attributes (`MasterUserPassword` instead of
  `password`). Rules reading `password` (339/710/850) miss. The
  response carries **no warning** that CFN detection failed.
- ARM: manifests does not recognise the document at all
  (`manifests: unrecognized document 1 …; skipped`), producing 0
  resources and 0 findings. A warning diagnostic is emitted, but a
  client that reads only `findings` sees a clean bill of health for
  a template with 35 findings.

Direct proof: calling the CFN adapter's `Parse` + the registry in a
test yields all 14 findings (including 339/710/850 with the
`password` attribute mapped); the API path on identical bytes
yields 11. The gap is purely the `Handles` disk-sniff.

**Impact.** Any API consumer scanning CFN or ARM content gets
false negatives — including the complete loss of hardcoded-credential
and weak-password detection on CFN, and total loss on ARM. The CLI
is unaffected (files exist on disk, so sniffing works).

**Recommended fix (not applied in this audit).** Give adapters a
content-aware selection path for in-memory scans — e.g. a
`HandlesContent(path string, src []byte) bool` method, with
`scanFilesInMemory` trying content-aware matching when name-based
`Handles` declines, and falling back to the current behaviour.
Alternatively, make `scanFilesInMemory` attempt CFN/ARM `Parse`
when manifests reports "unrecognized document". Either way, the
API must either detect these formats or return an explicit
diagnostic that format detection failed — never a silent 200 with
missing findings.

**Not fixed here** because this item is an audit; the fix touches
the adapter interface contract and deserves its own reviewed change.

### 2.7 API verdict

**PASS on security controls; FAIL on coverage parity (DEFECT-1,
High).** Authentication, validation, exhaustion, redaction, and
error handling all behave correctly. The API must not be presented
as equivalent to the CLI until DEFECT-1 is fixed: CFN and ARM
content scanned via the API is under-reported.

## 3. Reproduction

```sh
# Fix matrix (per project):
cp -r /tmp/vuln20/01-tf-aws-s3-iam /tmp/probe
aegis scan /tmp/probe --format json   # before
aegis fix /tmp/probe --apply
aegis scan /tmp/probe --format json   # after

# API defect:
aegis serve --addr=127.0.0.1:8734 --auth-token=t &
curl -X POST localhost:8734/v1/scan -H "Authorization: Bearer t" \
  -d '{"files":[{"path":"template.yaml","content":"<CFN with MasterUserPassword>"}]}'
# → 11 findings; CLI on the same file → 14 (missing 339/710/850)
```
