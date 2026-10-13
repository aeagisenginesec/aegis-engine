# Round-2 Evaluation Run Log

## Environment
- Date: 2026-10-12/13. Host: Linux sandbox (Hatch VM).
- Go toolchain: `~/gosdk/go/bin/go` (go 1.25.x; `go` not on default PATH).
- Python: system python3 + numpy 1.26.4.
- Scanner binaries:
  - Aegis: rebuilt from frozen commit `ddb934766e8b0199172a4b9f60049bd268932513`
    (`go build ./cmd/aegis`), sha256
    `9ae868d9d244361be46e074c1c74601b17198b2378605492171660dd2633738d`,
    at `docs/audit/raw/final-eval/aegis-frozen`. `aegis doctor`: 1,146 rules.
  - Checkov: `~/workspace/.venv-checkov/bin/checkov` v3.3.26 (verified).
  - KICS: `~/workspace/bin/kics` v2.1.20 (verified; must run from
    `~/workspace/kics/` with `--queries-path ./assets/queries`).
  - Trivy: `~/workspace/bin/trivy` v0.74.0, check bundle
    `sha256:1583562f…` cached 2026-10-12 (verified).
- GNU `time` NOT available (apt-installed copy was wiped); timing uses
  `timing_harness.py` (perf_counter wall + resource.getrusage peak RSS).

## Incident: /tmp wiped 2026-10-12 ~23:30 UTC
Sandbox restart cleared the 512M tmpfs. Lost: round-2 corpus (205 projects),
all 8 labeler files, adjudication outputs, all scanner raw outputs, scoring
working copies, timing subset, `/tmp/aegis-frozen`. Survived: everything under
`~/workspace` (repo, protocol, hygiene review, score.py). Full rebuild from
scratch with fresh corpus; paths relocated to
`docs/audit/raw/final-eval/{corpus,labels,scanner-output,scores}/`.
See protocol Addendum A.

## Corpus rebuild (fresh, blind)
- 3 author subagents (t: Terraform 70, c: CFN/ARM/Bicep/Pulumi 70,
  k: Docker/K8s/Compose/mixed 65), blind to Aegis rules, no copying prior corpus.
- Location: `docs/audit/raw/final-eval/corpus/`; manifest discipline:
  per-group backups `MANIFEST-{t,c,k}-backup.json` + read-modify-write appends
  to shared `MANIFEST.json`.
- k001–k065 complete (2026-10-12 ~23:39 UTC); t/c in progress.

## Protocol
`docs/audit/11_EVAL_PROTOCOL.md` (frozen pre-execution; Addendum A added
2026-10-13 for the /tmp incident — no methodological change).
Hygiene decisions: `docs/audit/raw/final-eval/hygiene-review.md`
(9 types reclassified with written justifications; AWS-004 kept scored).

## Analysis code (written BEFORE results)
- `score.py` — auto-scoring: normalized-pattern classification, (project,class)
  counting, hygiene exclusion set, per-scanner loaders.
- `fp_sample.py` — FP worklist export: full adjudication for aegis+checkov
  (fallback to seeded 1000-sample if either exceeds 1500 unmatched),
  seeded 400-samples for kics+trivy. Seed 20261013.
- `stats.py` — cluster bootstrap by project, B=10,000, two-level redraw for
  sampled FP fractions; decision rules per protocol §8.
- `timing_harness.py` — shared wall-time + peak-RSS harness.
- Timing subset (30 projects, stratified): `timing-subset.json`.

## Steps below appended as they complete

## Corpus verified (2026-10-13 ~00:00 UTC)
- 205/205 project dirs present (t001-t070, c001-c070, k001-k065), none empty,
  none without infra files, no exact-duplicate .tf files across projects.
- `corpus/MANIFEST.json`: 205 unique entries, all ids covered.
  Backups: `MANIFEST-t-backup.json` (70), `-c-` (70), `-k-` (65).
- Actual distribution — profile: 40.5% vulnerable / 25.4% secure / 34.1% mixed;
  difficulty: 29.3% easy / 44.9% medium / 25.9% hard; formats: tf 70, cfn 25,
  arm 15, bicep 15, pulumi 15, docker 20, k8s 20, compose 10, mixed 15.
- Removed empty leftover dir `corpus/_build/`.

## Execution wave launched (2026-10-13 ~00:05 UTC)
- Aegis accuracy+timing: `sweep_aegis.py` run directly by coordinator
  (background); outputs `scanner-output/aegis/`.
- 3 scanner sweeper subagents: checkov, kics, trivy → `scanner-output/<s>/`.
- 8 blind labeler subagents (A/B × chunks 1-4) → `labels/labels-<A|B>-chunk<N>.json`.
  All instructed: no MANIFEST.json, no scanners, no Aegis rules, no cross-reading.

## Incident 2: daemon restart 2026-10-13 ~00:38 UTC (no /tmp wipe this time)
- Killed the trivy sweeper at 63/205 and the kics sweeper after batch 1.
  Checkov sweeper and labelers survived or had completed.
- Partial outputs survived (persistent dirs): trivy 63 valid JSONs + scripts;
  kics batch1/results.json valid (150 queries, 38 ids attributed).
- Both sweepers re-spawned with resume briefs (verify-existing → complete
  the remainder → timing → RUNLOG).

## Aegis sweep complete (2026-10-13 ~00:20 UTC)
- 205/205 attempted via `sweep_aegis.py`: 184 exit 1 (findings), 19 exit 0,
  2 OOM failures (c043, c049 — kernel SIGKILL, exit -9).
- DEFECT (real, reproduced): Bicep `for`-comprehensions trigger unbounded
  memory growth — c043 (1602-byte main.bicep): RSS 2.5GB @ 5s → 3.7GB @ 30s.
  Same family as pre-wipe c045. Scoring: failed scans never zero-filled;
  c043/c049 concepts count as FN for Aegis.
- Timing (30-project subset, 5 runs): cold median 60.6ms, warm median 59.9ms.
  Clean per-process peak RSS: 14.9 MB (TIMING.json peak_rss_kb inflated by
  cumulative RUSAGE_CHILDREN including the OOM kills — documented).
- Details: `scanner-output/aegis/RUNLOG.md`.

## Labeling complete (2026-10-13 ~00:25 UTC)
- 8/8 labeler files schema-valid, 748 raw concepts. Adjudicator spawned.

## Matcher taxonomy refinement (2026-10-13 ~00:45 UTC — BEFORE any scanner scoring)- Concept-side diagnostics only (no scanner output seen): 71/416 firm concepts
  had no taxonomy class (17%).
- Extended `score.py` CLASS_RULES for clear taxonomy gaps, applied equally to
  all scanners: fixed camelCase-split bugs (`administratoraccess`→
  `administrator access`, `allusers`→`all users`, added spaced variants
  `host pid`/`ip forward`), removed the `multi region` negative that wrongly
  excluded CloudTrail-not-multi-region, and added 17 new classes
  (no-waf, lambda-public-url, cors-open, vm-password-auth,
  log-retention-short, k8s-secrets-no-encryption, kms-no-rotation,
  ecr-mutable-tags, storage-shared-key, acr-admin, sudo-nopasswd,
  curl-pipe-shell, git-exposed, docker-build-tools, dynamodb-no-cmk,
  gcp-iam-broad, gke-legacy-auth, db-no-ssl).
- Result: 1/416 classless (t068, overly-broad internal CIDR — no safe
  keyword, deliberately left; counts as FN for all scanners equally).
- This is analysis-code completion, not detection tuning: Aegis rules/code
  untouched; identical matcher for every scanner.

## KICS batches verified (2026-10-13 ~01:00 UTC)
- All 5 batches exit 0. Attribution: 177/205 projects with findings;
  13 scanned with zero findings (verified present in batch roots);
  15 pulumi projects scanned with zero findings = native skip
  (KICS 2.1.20 has no Pulumi queries) — legitimate, documented.
- 205/205 projects accounted for. Timing phase in progress
  (single-run-per-project documented deviation).

## Trivy complete (2026-10-13 ~00:55 UTC)
- 205/205: 165 OK, 40 native skips (bicep/pulumi/compose — no native
  scanner in 0.74.0), 0 failed. Accuracy ~8.2s/project.
- Timing (30×5): cold median 6.09s, warm median 6.53s.
- Full RUNLOG: `scanner-output/trivy/RUNLOG.md`.

## KICS complete (2026-10-13 ~01:05 UTC)
- 5/5 batches exit 0, 1327 findings (query×file pairs), 205/205 attributed.
- Timing (30×1, documented deviation): median single-run 28.9s
  (min 4.9s, max 153.8s on large terraform projects); peak RSS ~128-141MB.
- Full RUNLOG: `scanner-output/kics/RUNLOG.md`.

## Auto-scoring complete (2026-10-13 ~01:10 UTC) — BEFORE FP adjudication
- `score.py`: concepts with class 415/416. Auto TP/FN vs 416 firm concepts:
  aegis TP 244 / FN 172 (1613 findings); checkov TP 137 / FN 279 (1201);
  kics TP 92 / FN 324 (1327); trivy TP 112 / FN 304 (811).
- FP worklists (`fp_sample.py`, seed 20261013): aegis 1355 unmatched → FULL
  adjudication; checkov 1059 → FULL; kics 1234 → 400-sample; trivy 696 →
  400-sample. (Full-adjudication fallback threshold 1500 not triggered.)
- Sharded (`split_fp_shards.py`): 5+5+1+1 = 12 shards,
  `labels/fp-shards/fp-<scanner>-shard<i>.json`.
- 12 FP adjudicator subagents spawned with fixed TP/FP/HYGIENE/UNCERTAIN
  criteria, per-scanner file-resolution instructions.

## Criteria correction (2026-10-13 ~01:20 UTC) — availability/detection controls
- PROBLEM: the FP-adjudication briefs shortened the protocol's GENUINE
  criterion to "real, actionable security weakness or missing security
  control", omitting the protocol's explicit qualifier "(including
  availability and detection controls)". All 12 adjudicators consequently
  marked factually-correct availability/detection findings (RDS Multi-AZ,
  termination protection, enhanced monitoring, log exports, MSSQL auditing,
  S3 versioning, backups) as FP. The ground-truth adjudicator HAD included
  such controls as firm concepts (9 backup/audit/flow-log concepts) —
  inconsistent treatment.
- FIX: 144 pure availability/detection FP verdicts extracted
  (`labels/fp-shards/fp-readjudicate-avail.json`; 9 encryption-related
  matches excluded as out of scope) → ONE re-adjudicator re-judging them
  with the protocol criterion quoted verbatim. Factually-correct
  availability/detection findings flip FP→TP; factually-wrong ones stay FP.
- This applies the PRE-REGISTERED criterion correctly; it is not a
  threshold change. Applied equally to all scanners.

## Consistency correction #2 (2026-10-13 ~01:35 UTC)- PROBLEM: FP adjudicators marked factually-correct findings as FP with
  "availability/ops, not a security control" reasoning, while the ground
  truth contains FIRM concepts for the same condition classes
  (k8s-no-probe: 19 GT concepts vs 22 Aegis + 19 Checkov FP verdicts;
  docker-no-healthcheck: 42 GT vs 8 FP; s3-no-logging vs 6 FP; etc.).
- FIX: 100 FP verdicts whose justifications invoked "not security" AND whose
  finding class has firm GT concepts → ONE re-adjudicator verifying FACTUAL
  CORRECTNESS per finding. Factually-true findings flip FP→TP (class
  genuineness established by GT); factually-wrong ones stay FP.
- Note: AZURE-205 (Key Vault firewall w/o IP rules, 9 FPs) was correctly
  judged FP — vaults had publicNetworkAccess Disabled + Deny, so no public
  path; class overlap was coincidental. Not in scope.

## Final statistics (2026-10-13 ~02:00 UTC)
- `stats.py` (cluster bootstrap, B=10,000, 205-project frame):
  - Aegis: F1 0.367 [0.323,0.411], P 0.267, R 0.587, FP 0.733 [0.690,0.773]
  - Checkov: F1 0.245 [0.207,0.283], FP 0.805 [0.770,0.838]
  - KICS: F1 0.144 [0.119,0.170], FP 0.893 [0.873,0.913]
  - Trivy: F1 0.382 [0.326,0.437], P 0.658, R 0.269, FP 0.342 [0.250,0.432]
  - Diffs: F1 Aegis-Checkov +0.122 [+0.086,+0.159]; Aegis-KICS +0.223;
    Aegis-Trivy -0.015 [-0.073,+0.042] (contains 0).
    FP Checkov-Aegis +0.072 [+0.042,+0.104]; Trivy-Aegis -0.392 [-0.483,-0.302].
  - Timing medians: aegis 0.056s, checkov 6.36s (114x), trivy 6.60s (118x),
    kics 28.9s (519x).
- Methodology note: primary = protocol-§7 clean (TP/FN vs 416 firm concepts;
  adjudicated TP-missed excluded from FP numerator only). Sensitivity
  (additive TP-missed): Aegis F1 0.654 vs Trivy 0.804 — same verdict.
- Per-format F1 leaders: Aegis 4 (terraform, kubernetes, compose, mixed),
  Trivy 3 (cloudformation, arm, docker), Checkov 1 (bicep); pulumi 0 for all.
- Verdict: NOT YET — (a) FAIL (Trivy F1 numerically higher),
  (b) FAIL (Trivy FP decisively lower; Aegis beat Checkov decisively),
  (c) PASS (114-519x).
- Report: `docs/audit/11_FINAL_EVAL_REPORT.md`.
