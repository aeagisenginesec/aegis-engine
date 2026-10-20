# 26 — Aegis Final State (FP/FN Elimination Closeout)

Date: 2026-10-20 · Engine: aegis 2.0.0 · Branch:
`mission/gap-userdata-eol-image` · Registry: **1,140 active rules**,
67 deprecated IDs · Status: **closeout complete, tree clean, nothing
pushed** (release is the owner's call — see Open Issues).

This document closes Plan 24 (`24_FP_FN_ELIMINATION_PLAN.md`):
Sprint 1 (FN elimination), Sprint 2 (FP family kill), Sprint 3
(permanence apparatus), the R5 blind run, and the resumed closeout
verification. Companion reports: `25_FP_FAMILY_KILL.md`,
`raw/final-eval-r5/CLOSEOUT-RUN.md`,
`raw/final-eval-r5/PRECISION-RECONCILIATION.md`.

## 1. Accuracy — R4 adjudicated corpus (the bedrock)

Frozen protocol, 136 human-adjudicated ground-truth concepts:

| | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|
| Sprint baseline | 1.000 | 0.941 | 0.970 | 0 | 8 |
| **Final (Sprints 1–2, re-verified at closeout)** | **1.000** | **1.000** | **1.000** | **0** | **0** |

- Sprint 1 killed all 8 FNs (4 families: AWS-858 DB-port rule,
  AZURE-014 via the `enableRBAC` casing fix, COMPOSE-009 split,
  AZURE-263 Cosmos regression lock).
- Sprint 2 adjudicated all 2,227 FP candidates against source:
  2,065 TP / 142 NOISE / 20 factual FP — all 20 killed (15 duplicate
  rules deprecated, DOCKER-017/018 final-stage gating, AWS-311
  engine scoping).
- **Closeout re-verification (this document's run):** clean re-sweep
  from cleared outputs with the final binary — all 210 project
  outputs byte-identical to the Sprint 2 sweep; rescore **TP 136,
  FN 0, FP candidates 2,044** (commit `e853278`). The Sprint 3
  adapter fixes (storage fold, DDoS merge) moved none of the
  adjudicated numbers.

## 2. Accuracy — R5 blind corpus (report-only, uncontaminated)

210 sealed projects, 128 concepts, rules frozen before scoring;
**no fix in this closeout was derived from R5 results.**

- Auto recall **0.555** (TP 71 / FN 57) — up from 0.547 in the prior
  round; findings 1,263 non-hygiene.
- Carried adjudication precision 0.090 **does not survive
  re-verification** (see `PRECISION-RECONCILIATION.md`): of 142
  carried-"FP" items re-checked against corpus source (35-item
  stratified sample across 16 rules + full censuses of AWS-001,
  K8S-006, K8S-029, K8S-030), exactly **6 are factual FPs — all
  AWS-001**. The rest are factually accurate findings the prior
  adjudication scored as FP on materiality grounds ("pedantry",
  "by-design", "not a security control").
- Corrected precision: **0.79–0.92** on the scorer's definition;
  **≈0.98** factual precision over all non-hygiene findings. The
  blind-corpus problem is recall/coverage, not correctness.
- Prior documented FP bug signatures (AZURE-169/145/195/313/108):
  **all dead** in the closeout sweep. AWS-001 (6 firings) and
  K8S-027 (6 firings, carried HYGIENE) remain as open signatures.

## 3. Sprint 3 permanence apparatus (Part A audit + delivery)

Gap audit at closeout resume: both remaining brief items were
already delivered by the banked Sprint 3 commits — verified, not
rebuilt:

- **Regression locks** (`internal/regression/sprint_locks_test.go`,
  `9e8abd4`): end-to-end locks for AWS-858 (all SG forms),
  AZURE-014 (`enableRBAC` spelling, ARM + Bicep), COMPOSE-003/009
  split, DOCKER-017/018 final-stage gating.
- **Parity matrix** (same file): public S3 → AWS-104 from Terraform
  **and** Pulumi; storage public access → *identical rule sets* from
  ARM and Bicep incl. canonical AZURE-031; SG DB-port parity is the
  AWS-858 forms lock (inline / standalone / VPC rule forms).
- **Deprecated-registry lock**
  (`internal/rules/deprecated_registry_test.go`): the 15 Sprint 2
  duplicates stay unregistered.
- **Compliant-code FP budget gate**
  (`internal/regression/compliant_test.go` + `testdata/compliant/`,
  `67a0137`): six genuinely-compliant fixtures (Terraform, ARM,
  Bicep, K8s, Compose, Dockerfile) must produce zero non-hygiene
  findings.
- **CI gate** (`.github/workflows/ci.yml`): already wired — build,
  vet, gofmt check, `go test ./...`, race tests on sensitive
  packages, `aegis quality-gate`, determinism check. The apparatus
  above therefore gates every push/PR. (Authored 2026-10-14, not yet
  exercised against a real GitHub remote — the repo has never been
  pushed.)

### The gate caught a real bug during closeout

The compliant gate was **flaky**: AEGIS-AZURE-057 fired
intermittently (~1 in 5 runs) on the compliant ARM/Bicep VNets.
Root cause: `enableDdosProtection` (rename table) and
`ddosProtectionPlan` (snake_case) collide on the one IR attribute
`ddos_protection_plan`, and the adapter's first-writer-wins guard
let Go map iteration order pick the winner — plan-object wins →
block without `enable` → fire; bare bool wins → rule cannot decide.
Fixed deterministically by merging both properties into the single
TF block `{id, enable}` before the generic loop (`1e43208`, twin
tests incl. a 50× reparse determinism check). Gate after fix:
**100/100 clean**; full suite **32/32 ok in two consecutive
uncached runs**. Building the Sprint 3 fixtures had already caught
the sibling bug banked as `b5c1a5d` (ARM/Bicep storage child
services folded onto a phantom account).

## 4. Performance / final battery (final shipped binary)

`./aegis doctor`: all checks pass, 1,140 rules, go1.25.4.

| Target | Findings | Crit | Time (wall) | vs Sprint-2 close |
|---|---|---|---|---|
| TerraGoat (Terraform) | 513 | 7 | 0.23s | identical |
| vuln-500 (Terraform) | 4,426 | 288 | 0.28s | identical |
| Parity fixtures (mixed) | 1,159 | 27 | 0.23s | identical |
| k8s-vuln | 17 | 1 | 0.01s | identical |
| docker-vuln | 17 | 0 | 0.02s | identical |
| pulumi-vuln | 6 | 1 | 0.03s | identical |
| vuln-10000 | 97,574 | 4,910 | ~8.5s | see note |

vuln-10000 note: the historical benchmark (100,926 findings, doc 23)
predates Sprints 1–2. The −3,352 (−3.3%) is the Sprint 2 duplicate
deprecations at scale (vuln-500 shows the same −3.5% signature) plus
documented severity normalizations; **critical count is unchanged
(4,910)** and the run is deterministic (two runs, zero per-rule
diffs). The ~8.5s is subprocess wall time; the historical 5.4s was
in-engine scan time under a different harness.

## 5. Closeout commit inventory

Sprint 1: `41ab532` `ed18943` `47e0f13` `4f18e4d` `1cc4707`
`d0eda66` · Sprint 2: `c826f7b` `0907bc1` `76ed4ed` `336dff8`
`c6a246e` `e4939c8` `5e79bf4` `74f0a55` `c342aeb` `b3e3907` ·
Sprint 3 (banked): `9e8abd4` `b5c1a5d` `67a0137` · Closeout resume:
`1e43208` (DDoS merge fix), `e853278` (R4 closeout rescore), plus
the closing commits carrying the R5 artifacts
(`raw/final-eval-r5/CLOSEOUT-RUN.md`, `scanner-output/aegis-closeout/`,
`scores/closeout-scores.json`, `PRECISION-RECONCILIATION.md`), the
refreshed `docs/LIMITATIONS.md`, the rebuilt repo-root binary, and
this report. The branch sits **44 commits ahead of origin**; the
entire stack is local.

## 6. Open issues (honest list)

1. **R5 coverage frontier (recall 0.555).** FN profile: secret-
   hardcoded ×31 (template parameter defaults, PostgreSQL admin
   passwords, Pulumi config, Dockerfile ENV, `.env` files, K8s env
   literals), sg-admin-public ×5, ecr-public-policy ×5,
   compose-db-port-published ×4, apigw-no-auth ×3,
   ebs-snapshot-public ×3, k8s-cap-sys-admin ×3, kafka-plaintext ×2.
   These are new coverage classes for a future round — fixing them
   requires fresh ground truth, not R5-derived tuning.
2. **AWS-001 factual FP family** (6 verified): rule demands explicit
   SSE config; S3's default is encrypted. Fix = platform-default
   awareness in the rule; deferred to keep the blind set clean.
3. **AWS-001-adjacent signature K8S-027** (6 firings, carried
   HYGIENE): unchanged; hygiene-class, not an FP.
4. **Twin resource identity:** same-named instances in one file
   share one resource ID (7 twin-ambiguous R5 firings); spans are
   the only disambiguator.
5. **AZURE-263 absence policy:** adjudicated correct for Cosmos
   (default = Enabled) and left in place; it is a documented
   exception to the explicit-only pattern used elsewhere.
6. **Eval-side inconsistency (not an engine bug):** AWS-677 is
   scored while its twin AWS-798 is hygiene-excluded in the R4
   scorer; AWS-684's hygiene entry is vestigial (rule already
   deprecated to AWS-565).
7. **Unpushed stack:** 44 commits await the owner's GitHub
   credential (secure entry). Nothing in this closeout has been
   pushed, tagged, or released; the version const remains `2.0.0`
   and the v2.0.0 tag is untouched — version bump / tag / release
   are the owner's separate call.
