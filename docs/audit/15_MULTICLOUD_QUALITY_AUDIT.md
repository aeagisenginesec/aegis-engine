# 15 — Multi-Cloud Finding Quality Audit

**Fixture:** `~/workspace/multicloud-test/aegis_multicloud_vulnerable/`
(AWS + Azure + GCP Terraform, 256 lines; credentials are fake placeholders;
never `terraform apply`.)
**Canonical pre-fix output:** `~/workspace/multicloud-test/results/aegis-run1.json`
(133 findings, byte-identical across 5 runs) + `aegis.sarif`.
**Post-fix output:** `~/workspace/multicloud-test/results-post-audit/aegis-run*.json`
(131 findings, byte-identical across 5 runs).
**Scanner:** release binary rebuilt from the audited tree
(`~/workspace/your_files/aegis-linux-amd64`).
**Status:** audit + fixes complete. **Nothing is committed** — all changes are
uncommitted in the working tree. See §13 for the concurrent-work collision
(AEGIS-AWS-856) that leaves two count assertions red.

## 1. Verdict summary

| Measure | Pre-fix (133) | Post-fix (131) | Note |
|---|---|---|---|
| Duplicate findings removed | — | 9 | 8 Azure SQL + 1 GCP scope (same condition, two rules) |
| Parser-artifact false firing removed | — | 1 | GCP-214 (see §3, cluster 3) |
| True positives added (misses fixed) | — | 8 | 005, 040, 068, 293, 294, 534, 538, 710 |
| Evidence corrected, detection unchanged | — | 1 | GCP-014 (range in evidence) |
| Non-AWS findings with AWS-specific remediation | 63 | **0** | cloud-aware fallback (§6) |

No precision/recall is claimed: the fixture has no independently verified
ground-truth labels, so those metrics would be circular. The counts above are
verified finding-by-finding against fixture evidence and rule code (see §2).

**Headline:** the audit found the engine's detections on this fixture were
largely sound, but the *parser* was silently dropping attributes from
comma-separated single-line blocks, which caused one false firing
(GCP-214), one mis-evidenced firing (GCP-014), and six missed findings
(005, 040, 068, 538, 710, plus the two known misses 534/293/294 handled
separately). Fixing the parser exposed those, and fixing the parser
introduced a span-drift defect (findings pointed at wrong lines) that was
then fixed with a repaired→original line map (§8). Nine duplicate rules
were removed and the remediation fallback was made cloud-aware.

## 2. Finding accounting (verified)

### 2.1 Removed — 9 duplicates (condition genuinely present, reported twice)

| Removed rule | Canonical survivor | Reason |
|---|---|---|
| AEGIS-AZR-004 (SQL public access, High) | AZURE-106 | Exact duplicate of 048; subset of 106 |
| AEGIS-AZURE-008 (SQL no AD auth, High) | AZURE-107 | Same inline-block-only check as 047/225; FP-prone on standalone form |
| AEGIS-AZURE-009 (SQL no auditing, High) | AZURE-101 | Same inline-block-only check as 045; FP-prone on standalone form |
| AEGIS-AZURE-025 (SQL TLS, High) | AZURE-105 | Subset (present non-1.2 only) of 105 (also fires on absent) |
| AEGIS-AZURE-045 (MSSQL no auditing, Medium) | AZURE-101 | Same check as 009 |
| AEGIS-AZURE-047 (MSSQL no AD admin, Medium) | AZURE-107 | Same check as 008 |
| AEGIS-AZURE-048 (MSSQL public access, High) | AZURE-106 | Exact duplicate of AZR-004 |
| AEGIS-AZURE-225 (SQL no Entra ID admin, Medium) | AZURE-107 | Exact duplicate of 047 ("Entra ID" = renamed Azure AD) |
| AEGIS-GCP-063 (full cloud-platform scope, High) | GCP-018 | Exact duplicate of 018 with a looser `Contains` match |

On **this fixture** the 9 were duplicates, not false positives: the SQL
server uses the legacy inline form, so the conditions were genuinely
present and the survivors fire. The FP-prone aspect is real but latent:
a server configured **only** via the standalone
`azurerm_mssql_server_azuread_administrator` resource (or standalone
auditing-policy resource) would have received 3 false positives from
008/047/225 (and 009/045 for auditing) while 107/101 stayed correctly
quiet. Proven by code reading; the canonical survivors (101/107) check
both the inline block **and** the standalone resource. 101 was extended
to also cover legacy `azurerm_sql_server`. Severity note: 008 was High
and 047 Medium for the same check; the survivor 107 is Medium, which
resolves the inconsistency toward Medium.

These removals fix proven duplicates / latent FPs. They are **not**
count-tuning: no rule was removed to make a number smaller, and every
removed condition is still covered by its survivor.

### 2.2 Removed — 1 parser-artifact false firing

**AEGIS-GCP-214** ("firewall allows all ports", High) fired on the
fixture because the parser dropped the `ports` attribute from the
comma-separated single-line `allow` block, so the rule's "no ports key"
condition appeared true. The fixture **does** specify ports (`0-65535`).
Post-fix the ports parse, the rule's condition is false, and it correctly
stays quiet. The rule itself was correct; the firing was a parsing
artifact. Its evidence text ("no ports (all ports)") was accurate for its
firing condition — the defect was upstream, in the parser.

### 2.3 Added — 8 true positives (misses fixed)

| Rule | Finding | Why it was missed |
|---|---|---|
| AWS-005 (Medium) | SG egress open to world (`web_open`) | Parser dropped `cidr_blocks` (2nd+ arg of single-line `egress` block) |
| AWS-534 (High) | Secret via `${var.database_password}` in EC2 `user_data` | Interpolated template was invisible to the rule (see §7) |
| AWS-538 (High) | Plaintext default for secret-like variable `database_password` | Parser dropped `default` (3rd arg of single-line `variable` block) |
| AWS-710 (Medium) | RDS master password not managed by Secrets Manager | Parser dropped the `password` attribute's surroundings (see below) |
| GCP-040 (Critical) | Cloud SQL allows connections from the internet (`authorized_networks` 0.0.0.0/0) | Parser dropped `value` (2nd arg of single-line `authorized_networks` block) |
| GCP-068 (Critical) | Firewall allows all ports from the internet | Parser dropped `ports`; the rule needs the ports list to judge "all ports" |
| GCP-293 (Critical) | Secret in instance metadata startup-script (`password=WeakPassword123!` → `/tmp/app.conf`) | No rule covered metadata scripts (new rule, §7) |
| GCP-294 (High) | Compute instance on end-of-life OS image (Debian 10) | No rule covered VM image age (new rule, §7) |

AWS-710's pre-fix miss: the RDS block's `password` attribute was parsed
(the finding is on `password`), but the rule's condition also depends on
`manage_master_user_password` handling in the same block region affected
by single-line parsing; post-fix the rule fires. The evidence
(`[REDACTED]`, expected `manage_master_user_password=...`) matches the
fixture (RDS uses `password = var.database_password`, no Secrets Manager
management).

### 2.4 Corrected evidence — GCP-014

GCP-014 fired pre-fix **via the wrong branch**: with `ports` dropped by
the parser, the rule's no-ports-list fallback ("no ports = all ports")
fired, and the evidence said `tcp:22 from 0.0.0.0/0` — phrased as if
port 22 were listed, when the allow block was actually `tcp 0-65535`.
Post-fix the rule matches the port **range** (`parsePortRange`) and the
evidence reads `tcp 0-65535 from 0.0.0.0/0 (includes port 22)`. Same
detection, honest evidence. The range fix also closed a second gap in
the same function: `protocol = "all"` with no ports list was previously
missed entirely (now fires, with evidence `all (all ports)`).

### 2.5 Not individually re-verified

The remaining 122 pre-fix findings were inventoried (rule, severity,
resource, file/line, evidence, remediation) but not each re-traced to
code in this audit. No evidence of additional false positives was found
in the investigated clusters, but those 122 are **not** individually
certified here. A full per-finding trace of all 122 is future work (see
§14).

## 3. Cluster verdicts

### Cluster 1 — Azure SQL (`azurerm_mssql_server.public_sql`, 16 → 8 findings)

| Condition | Findings | Verdict |
|---|---|---|
| Public access | AZR-004, AZURE-048 (removed); AZURE-106 (survivor) | Duplicates removed; 106 is the correct canonical check (fires on present-true **or** absent, since the provider default is true) |
| AD/Entra auth | AZURE-008, 047, 225 (removed); AZURE-107 (survivor) | Duplicates + latent FPs removed; 107 correctly counts both the standalone administrator resource and the legacy inline block |
| Auditing | AZURE-009, 045 (removed); AZURE-101 (survivor) | Duplicates + latent FPs removed; 101 correctly counts the standalone policy resource, the legacy inline block, and (new) legacy `azurerm_sql_server` |
| TLS | AZURE-025 (removed); AZURE-105 (survivor) | Subset removed; 105 covers present-non-1.2 **and** absent |
| Retention | AZURE-102 (Low) | Distinct control (retention < 90d); kept |

Post-fix the server yields 8 findings, one per distinct condition. The
fixture genuinely has all of them (public access on, TLS 1.0, no AD
admin, no auditing, short retention).

### Cluster 2 — Azure NSG (`azurerm_network_security_group.open`, 4 findings)

The NSG has **one** inline rule, `AllowAllInbound` (all protocols/ports,
source `*`). All four findings fire on it:

| Rule | Verdict |
|---|---|
| AZURE-053 (RDP open) | Overlapping (specific) — legitimate: the rule answers "is RDP open?" |
| AZURE-054 (SSH open) | Overlapping (specific) — legitimate: same, for SSH |
| AZURE-055 (all ports open) | Overlapping (specific) — legitimate: same, for the all-ports case |
| AZURE-244 (generic inline rule) | Overlapping (generic) — legitimate layering: the catch-all covers ports no specific rule names (e.g. 8080) |

**Verdict: overlapping, not duplicate.** This is the designed layering
(specific-port rules + a generic catch-all). The implementations were
not fully re-read in this run, so this verdict is **provisional** — it
rests on the prior session's evidence trace plus the finding set, not a
fresh line-by-line read of all four rules. No change made.

### Cluster 3 — GCP firewall (`google_compute_firewall.allow_all`, 5 → 4 findings)

| Rule | Verdict |
|---|---|
| GCP-002 (open to world) | Distinct (world-exposure condition) |
| GCP-014 (SSH open) | Distinct, evidence corrected (§2.4) |
| GCP-069 (no flow logging) | Distinct |
| GCP-214 (all ports) | Parser-artifact false firing — removed by the parser fix (§2.2). The rule is retained: it correctly fires when an allow block genuinely omits `ports` |
| GCP-215 (no description) | Distinct (hygiene-class) |
| GCP-068 (all ports from internet) | **New** post-fix TP (§2.3) — distinct from 214: 068 judges "ports list covers all ports", 214 judges "ports list omitted" |

### Cluster 4 — GCP service-account scope (`google_compute_instance.public_vm`)

GCP-018 vs GCP-063 were **exact duplicates** on the identical
attribute/value (`service_account.scopes` = cloud-platform URL). 063
(looser `Contains` match, subsumed by 018's exact/suffix match) was
removed; 018 survives. The other instance findings (017 public IP, 059
secure boot, 060 OS Login, 061 boot-disk CMK, 062 default SA, 173
Confidential VM, plus new 293/294) are distinct conditions.

### Cluster 5 — AWS attack path (AWS-103 / AWS-629 + underlying findings)

| Rule | Verdict |
|---|---|
| AWS-103 (Public RDS exposure path) | Legitimate layered meta-finding. `PubliclyExposed` returns true for RDS with `publicly_accessible=true`; `pickPathSG` requires an actually-attached open SG. Fixture: internet → `web_open` (attached, world ingress) → RDS. Accurate. **Caveat:** the fixture defines a VPC but **no subnet resources**; `publicly_accessible=true` requires a public subnet at apply time. The finding does not state that assumption — an unstated-assumption gap, not a false positive. |
| AWS-629 (Full kill chain: INTERNET → web_open → legacy_web → public_database) | Legitimate layered meta-finding. High (not Critical — no IAM hop: the EC2 has no `iam_instance_profile`). The EC2→RDS hop is a shared-SG / stepping-stone hop, **not** a proven credential hop, and the finding does not claim credential use. Uncertain chains downgrade to Medium per the rule's contract. |
| Underlying (004 SG open, 011 RDS public, etc.) | Distinct base findings; the meta-findings layer on top without duplicating them. |

## 4. Severity disagreements

- **AZURE-008 (High) vs AZURE-047 (Medium)** for the same check —
  resolved by removing both; survivor AZURE-107 is Medium.
- **TF-003 (Medium)** "without pinned version" for open-ended `>=`
  constraints (e.g. `>= 5.0`). Title is shorthand; description
  clarifies it fires on open-ended ranges. Severity Medium is
  defensible-but-aggressive for a constraint that still bounds below.
  **Flagged, not changed** — downgrading without evidence would be
  severity-tuning, and the rule's behavior is documented.
- **New rules:** GCP-293 literal = Critical / taint = High (mirrors
  AWS-534/339); GCP-294 = High (mirrors GCP-200's EOL treatment).
  AWS-534 taint = High (mirrors AWS-339's taint severity); literal =
  Critical. Consistent.

## 5. The two known misses — verdicts

### 5a. Secret in EC2 `user_data` — TRUE MISS, now fixed (AWS-534)

`aws.tf` writes `${var.database_password}` to world-readable
`/tmp/deploy-creds.txt` (chmod 644). The hardcoded-creds rule correctly
stays silent on var references — but the **exposure pattern** (a secret
flowing into user_data) was uncovered. Root cause: the adapter returned
the interpolated heredoc as `Known=false`, plain Unknown, with **no
text**, so the rule's secret scan saw an empty string. Fix (prior
session, F4; verified in this run): the adapter preserves the raw
template on Unknown values (`ir.Value.Template` — literal parts
verbatim + `${ref}` placeholders, never a resolved value), and 534
scans it: literal secrets in the static parts → **Critical**; bare
`${var.<secret-like-name>}` / `${local.<secret-like-name>}`
interpolations → **High** taint finding with
`[REDACTED via ${ref} in user_data]` evidence (secret values never
appear in findings). Complex interpolations (e.g.
`${upper(var.x)}`) are opaque → quiet. Post-fix the fixture yields one
High 534 finding citing `var.database_password`.

### 5b. Debian 10 image — MISSING RULE, not a parser defect (GCP-294)

`gcp.tf` line 19: `initialize_params { image = "debian-cloud/debian-10", ... }`.
**Parser-vs-rule determination: RULE.** The parser was **not** the
cause: `image` is the first argument of the single-line block, so it
survived even the old partial parse. The miss was a missing rule: the
only EOL rule in the GCP pack was GCP-200 (Cloud Functions runtimes).
New rule GCP-294 (High) checks `boot_disk.initialize_params.image`
against a curated EOL family table (Debian 9/10, Ubuntu 16.04/18.04,
CentOS 7/8, Windows 2012/2016, RHEL 7), handling family names, image
names, and full self-links, with dash-delimited prefix matching
(`debian-10-v20230101` matches; `debian-101` does not). Interpolated
image values stay quiet (version undeterminable). Post-fix the fixture
yields one High 294 finding on line 19.

## 6. Remediation mismatches — fixed (cloud-aware fallback)

`RemediationFor` falls back to `fallbackRemediation(ruleID)` for rules
without a detailed DB entry. The fallback was **entirely AWS-specific**
(AWS doc links, `aws ec2 describe-security-groups`, CIS AWS Benchmark)
and was served for Azure/GCP/Terraform rules. Pre-fix, **63 of 133**
findings carried AWS-specific remediation on non-AWS resources
(50 "Review the flagged configuration against AWS security best
practices…" default + 13 "Remove public exposure… front it with a load
balancer… Verify with `aws ec2 describe-security-groups`" on storage
accounts, Key Vault, SQL servers, firewalls, buckets).

Fix (prior session, F3; verified in this run): the fallback dispatches
on rule-ID prefix — AZURE/AZR → Azure (`az …` commands,
`learn.microsoft.com`, Key Vault, Entra ID), GCP → GCP (`gcloud …`,
`cloud.google.com`, Secret Manager, Cloud Armor), K8S → K8s
(NetworkPolicy/RBAC/audit logs, `kubernetes.io`), DOCKER/COMPOSE →
container (`docs.docker.com`), AWS → original text byte-identical,
everything else (TF, ALI, OCI, SC, unknown) → cloud-neutral (CIS
Benchmark link only, no cloud-specific names/commands).
**Post-fix verification: 0 non-AWS findings carry AWS markers**
(checked against `amazonaws`, `cloudtrail`, `aws secrets manager`,
`cis aws`, `describe-security-groups`, `cloudwatch`,
`elbsecuritypolicy`, `iam access analyzer`, standalone word `aws`,
`arn:`). A regression test pins this for every non-AWS rule.

## 7. New rules added in this session (F5/F6)

### AEGIS-GCP-293 — Secret in instance metadata startup script (Critical / High taint)

Scans `metadata` map values (`startup-script`, `user-data`), `metadata`
blocks, and top-level `metadata_startup_script`, for literal secrets
(Critical) and secret-like var/local interpolations (High taint),
mirroring AWS-534. `startup-script-url` is excluded (a reference, not
content). **Limitation:** metadata **map** values containing
interpolations are not scanned — the adapter drops the template when an
object constructor has a non-static element (the whole map becomes plain
Unknown). Top-level `metadata_startup_script` interpolations **are**
covered. Fixing nested-template preservation in object constructors is
a larger adapter change, left as future work.

### AEGIS-GCP-294 — Compute instance on end-of-life OS image (High)

See §5b. **Limitation:** the EOL table is a curated snapshot — it needs
maintenance as vendors publish new EOL dates (Debian 11 EOLs June
2026, Ubuntu 20.04 EOLs April 2025 — both already past at audit time
but not in the table; the table covers the families the audit verified,
not every EOL release). The table should be reviewed on a schedule.

### Pattern fix (this session)

The secret-assignment regex in **both** packs had two silent gaps:
bare `token=` was not matched (the alternation only had
`auth[_-]?token`, despite the comment claiming `token=`), and
`secret_key=` / `private_key=` were not matched. Fixed in
`genericSecretPattern` (AWS) and `gcpSecretPattern` (GCP):
`(password|passwd|pwd|secret|token|api[_-]?key|auth[_-]?token|secret[_-]?key|private[_-]?key)`.
AWS-534 tests still pass; GCP-293 tests cover the new alternations.

### GCP-014 range parsing (this session)

`allowHasPort` now parses port ranges (`0-65535`, `8000-9000`) instead
of exact-string equality only, reports the matched allow entry for
evidence, and treats `protocol = "all"` with no ports list as matching
(previously missed). See §2.4.

## 8. Parser defect + span-drift fix (F1 + F1b)

### F1 — Comma-separated single-line blocks (fixed, prior session)

`lenientParseConfig`'s repair loop handled "Invalid single-argument block
definition" by inserting `\n` after `{`, but commas are not valid
block-body separators in HCL, so the next parse still errored, the loop
stalled, and recovery fell back to the strict partial parse keeping
**only the first argument** of each comma-separated block. The fix
converts each top-level comma on the block's line to `\n` (delete 1,
insert `\n`), skipping commas nested in brackets/braces/parens,
strings, and comments. This recovered the dropped attributes behind
005/040/068/538/710/214/014-evidence (§2). The 13 CLI parser
diagnostics on the fixture are now **0**.

### F1b — Span drift on repaired files (fixed, this session)

The F1 fix introduced a correctness defect: findings on attributes
inside repaired blocks pointed at **repaired-text line numbers**, not
the user's file (e.g. the SG egress finding reported line 48 for a rule
on line 44; the SQL `authorized_networks` finding reported line 73 for
line 61). Before F1, spans were accurate because the repair path failed
and the fallback used the original source.

Fix: `lenientParseConfig` now also returns a `lineMap` that aligns the
repaired source against the original (repairs only insert `,`, insert
`\n`, or replace `,` with `\n`, so every repaired line is a fragment of
exactly one original line). The map records, per repaired line, the
original line, the original column of the fragment's first byte, and
the fixed columns of inserted commas on that line (an inserted `,`
shifts later columns on the same line by one). `ParseModule` remaps
every span (resources, synthetic resources, variables, locals, module
calls, diagnostics) back to original coordinates before returning.
**Post-fix verification:** 005 → line 44, 040 → line 61, 068 → line 10,
294 → line 19 — all exact. Tests: unit tests for the line-map alignment
(incl. the inserted-comma column shift) + end-to-end ParseModule span
tests (egress/ingress blocks, object-constructor separator).

## 9. Per-cloud coverage (fixture findings)

| Cloud | Pre-fix | Post-fix | Delta |
|---|---|---|---|
| AWS | 36 | 40 | +4 (005, 534, 538, 710) |
| AZR | 3 | 2 | −1 (AZR-004) |
| AZURE | 49 | 42 | −7 (008, 009, 025, 045, 047, 048, 225) |
| GCP | 42 | 44 | −2 (063, 214) +4 (040, 068, 293, 294) |
| TF | 3 | 3 | 0 |
| **Total** | **133** | **131** | **−2** |

Post-fix severity mix: GCP 5 Critical / 9 High / 15 Medium / 15 Low;
AWS 16 High / 9 Medium / 15 Low; AZURE 14 High / 19 Medium / 9 Low;
AZR 1 High / 1 Medium; TF 3 Medium. No Critical AWS/Azure findings on
this fixture; the two Criticals are GCP (040, 068) plus 293.

## 10. Pulumi TypeScript/JavaScript — confirmed, separate work item

**Confirmed:** a Pulumi TypeScript program (S3 bucket with
`acl: "public-read"`, open security group) and a JavaScript program
(public S3 bucket) both return **0 findings**. The scanner only reads
`Pulumi.yaml` YAML programs (with a `resources:` section); `.ts`/`.js`
files are not even discovered (completeness: `files_discovered: 1`,
the `Pulumi.yaml` only). The emitted warning ("has no resources:
section; nothing to scan") is honest but does not name the skipped
`.ts`/`.js` files, so a user can mistake "0 findings" for "clean".

**Fix estimate (not attempted — a full TS/JS parser build is out of
scope for this audit):**
- Honest-reporting fix (~0.5 day): surface "Pulumi program files present
  but not parsed" as a scan-completeness warning listing the `.ts`/`.js`
  files, so 0 findings can never be misread as clean.
- Heuristic extraction (3–5 days): regex/AST-light extraction of
  `new aws.<Type>(name, {args})` constructions + arg mapping for the
  highest-value resources (S3, SG, IAM, RDS), with tests. Still misses
  dynamic constructs (loops, conditionals, components, `apply`).
- Full parser (2–4 weeks): TypeScript AST (Go-native parser or
  tree-sitter bindings) + evaluation of Pulumi's programming model,
  plus ongoing maintenance. Likely needs a Node.js sidecar or a
  Go-native TS parser.

## 11. K8s remediation

The wrong-cloud remediation class was confined to the fallback: a
script check of all 17 non-AWS DB entries found **zero** AWS markers.
The F3 cloud-aware fallback now serves K8s-appropriate text
(NetworkPolicy/RBAC/audit logs, `kubernetes.io`) for K8S-* rules. No
K8s DB entry needed changing. No K8s findings occur on this fixture.

## 12. Changes made

**Whole-tree diff stat (uncommitted):** `60 files changed, +2334/−1745`.
This covers the entire uncommitted working tree, which includes
pre-existing uncommitted work from earlier missions (Trivy-mission
leftovers, the concurrent AWS-856) alongside this audit. The
audit's own changes are the files listed below; shared files
(e.g. `secrets_deep.go`) also contain prior-session work.

### This session (audit F5/F6/F7 + span fix)

| File | Change |
|---|---|
| `internal/rules/gcp/gcp9.go` | New GCP-293 (metadata secret) + GCP-294 (EOL image); `gcpSecretPattern` extended (token / secret_key / private_key) |
| `internal/rules/gcp/gcp9_test.go` | 12 tests for 293/294 (literal, block, top-level, user-data, URL ignored, clean, taint, clean-var, Debian 10, supported images, EOL variants, near-miss `debian-101`, no-boot-disk, unknown image) |
| `internal/rules/gcp/gcp2.go` | `allowHasPort` rewritten: range parsing, matched-entry evidence, `protocol="all"` + no-ports fix; GCP-014 evidence now cites the matched entry |
| `internal/rules/gcp/gcp2_test.go` | 3 new 014 tests (range fires with range in evidence, range-excluding-22 quiet, all-protocol-no-ports fires) |
| `internal/rules/gcp/gcp_test.go` | Full GCP ID list: 293/294 appended |
| `internal/rules/aws/secrets_deep.go` | `genericSecretPattern` extended (same two gaps as GCP) |
| `internal/adapter/terraform/terraform.go` | `lineMap` (repaired→original alignment incl. column offsets + inserted-comma tracking), `remap*` walkers, `lenientParseConfig` returns the map, `ParseModule` remaps all spans |
| `internal/adapter/terraform/terraform_test.go` | `TestRepairedLineMap`, `TestRepairedLineMapInsertedComma`, `TestLenientSpansMapToOriginalLines`, `TestLenientObjectSeparatorSpan` |
| `benchmark/parity/fixtures/**` (22 files) | `expect.json` surgically updated: deprecated tuples removed, GCP-014 added to the 2 network-ingress-gcp vuln fixtures, `finding_total` + `determinism_hash` recomputed with the record.py formula. `record.py` wholesale was run once and **reverted** — it rewrote formatting across all files; only the 22 genuinely-changed files were kept. |

### Prior session (audit F0–F4, in the same uncommitted tree)

Parser comma repair (`terraform.go`), 9 rule deprecations + deprecation
map (51 entries) + doc, cloud-aware fallback remediation
(`remediation.go`), AWS-534 template support (`ir.go` Template field +
`secrets_deep.go`), Azure-101 legacy-type extension. These were
verified in this run (parity, suite, benchmark, remediation scan).

### Deliberately NOT changed

- The fixture (untouched). Historical benchmark results (untouched;
  post-fix runs went to `results-post-audit/`).
- TF-003 severity/wording (flagged §4, not changed).
- AWS-204's `[REDACTED]` evidence: output-layer redaction in
  `redactServeFindings`/`redactFindings` (attribute contains `token`),
  not a rule defect. Evidence value is correct in-engine.
- AWS-103's unstated subnet assumption (§3, cluster 5): flagged, not
  changed (wording change to a meta-finding's description needs
  product-level sign-off on the claim language).
- AEGIS-AWS-856 (see §13).

## 13. Concurrent-work collision — AEGIS-AWS-856 (NOT this audit's work)

During this session another agent added `AEGIS-AWS-856` (EC2 instance
on an end-of-life OS image, `internal/rules/aws/eol_image.go` +
registration in `pack.go`) to the same uncommitted tree. It is a
legitimate-looking rule (doc comment references GCP-294 as the GCP
counterpart) but it has **no test file**, and it was not reviewed in
this audit. Its effects on this audit's verification:

- Full suite: **all tests pass except 2 count assertions** that fail
  solely because AWS-856 raised the rule count by 1:
  `TestDefaultRegistry_HasAllPacks` (expects 1152, got 1153) and
  `TestPack_HasExpectedRulesWithUniqueIDs` (checks 473, got 474; its
  failure message misleadingly says "expected 475" — a pre-existing
  inconsistency in that test).
- Quality gate on the current tree: **FAIL solely on rule-coverage
  357/358** — "missing positive: AEGIS-AWS-856; missing negative:
  AEGIS-AWS-856". All other gate checks pass (precision 100%,
  recall 100%, performance p95 91.7ms, parser-safety 15/15).
- Benchmark: AWS-856 does **not** fire on the multi-cloud fixture (the
  EC2 AMI is an opaque ID / no OS marker), so the 131-findings result is
  unaffected by it.
- This audit did **not** touch AWS-856, its registration, or the count
  tests — updating counts to absorb another agent's unreviewed work
  would misrepresent this audit. The counts should be reconciled when
  AWS-856's owner adds its tests.

## 14. Verification

- **Full suite:** `go test ./...` — all packages pass except the 2
  count assertions in §13 (concurrent AWS-856).
- **Race:** `go test -race` on all touched packages
  (`adapter/terraform`, `ir`, `rules`, `rules/azure`, `rules/gcp`,
  `rules/aws`) — clean. (Run before AWS-856 landed; the race run
  covers this audit's packages.)
- **Quality gate:** `./aegis quality-gate` — PASS 5/5 on the
  pre-AWS-856 build (precision 100%, recall 100%, rule-coverage
  357/357, performance median 26.8ms / p95 41.4ms, parser-safety
  15/15). On the current tree it FAILs only on AWS-856's missing
  test evidence (§13).
- **Determinism:** 5 post-fix runs → byte-identical JSON (single
  sha256 `70987223…`).
- **Parity:** `TestParityRegression` green after the 22 surgical
  `expect.json` updates (§12). The only non-deprecation parity change
  was the justified GCP-014 firing on `network-ingress-gcp` (fixture
  firewall is `tcp 0-65535` from `0.0.0.0/0` — SSH genuinely open).
- **Benchmark (multi-cloud fixture, 5 runs each):**

| | Pre-fix | Post-fix |
|---|---|---|
| Findings | 133 | 131 (−10 removed, +8 added) |
| JSON bytes/run | 162,969 | 156,658 |
| Wall time | 0.01–0.03 s | 0.02–0.07 s (run 1 cold) |
| Peak RSS | 19.2–19.9 MB | 19.8–20.6 MB |
| Parser diagnostics | 13 | **0** |
| Determinism | byte-identical | byte-identical |

Performance is unchanged within noise. The finding-count change is
**not** a target — it is the arithmetic of §2 (duplicates/artifact out,
misses in).

## 15. Remaining limitations

1. **122 pre-fix findings not individually re-traced** (§2.5).
2. **NSG cluster verdict is provisional** (§3, cluster 2) — specific
   rule implementations not fully re-read this run.
3. **Metadata-map interpolations** not scanned by GCP-293 (§7).
4. **EOL tables are curated snapshots** (GCP-294 §7; AWS-856 is not
   this audit's).
5. **Pulumi TS/JS returns zero findings** (§10) — needs the
   honest-reporting fix at minimum.
6. **AWS-103's subnet assumption unstated** (§3, cluster 5).
7. **TF-003 severity/wording** flagged, not changed (§4).
8. **AWS-856 (concurrent)** unreviewed, untested, blocks the gate
   and two count tests (§13).
9. **Span remap edge cases:** spans pointing exactly at an inserted
   comma (should not occur — parser separators are not part of token
   ranges) and spans spanning an entire repaired file are mapped
   endpoint-wise; both are covered by the fallback (nil map → identity)
   if alignment ever fails.
10. **Parser repair is bounded** (2048 iterations / 16 MiB budget):
    pathologically sloppy files still fall back to the strict partial
    parse with original diagnostics. Unchanged behavior, still true.
