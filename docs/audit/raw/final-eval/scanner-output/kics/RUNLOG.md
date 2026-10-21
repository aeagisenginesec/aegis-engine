# KICS 2.1.20 final-eval sweep — RUNLOG

## Binary / version
- Binary: `~/workspace/bin/kics` → `Keeping Infrastructure as Code Secure 2.1.20`
- Queries: `~/workspace/kics/assets/queries` (full KICS 2.1.20 query library; cwd MUST be `~/workspace/kics`)

## Resume context (daemon restart after batch 1)
- Prior worker scanned batch1 on 2026-10-12 ~23:48–23:59 UTC (WALL_SEC=627.97, PEAK_RSS_KB=157304,
  exit 0) and died before batches 2–5.
- Scratch batch roots 2–5 (with `corpus/<id>/` copies) survived under
  `~/workspace/eval2-kics-harness/scratch/batch{2..5}/` — byte-verified against the corpus before reuse.
- Resume run: 2026-10-13 ~00:01–00:15 UTC (Africa/Casablanca = UTC+0). Corpus: READ-ONLY
  at `~/workspace/aegis-engine/docs/audit/raw/final-eval/corpus/` (205 project dirs: t001-t070, c001-c070, k001-k065).
- batch1/results.json kept AS-IS (byte-verified valid JSON; 150 queries with results, files_scanned=58).
  Only added the top-level convenience copy `batch1-results.json` (needed by the attribution script);
  the original in `batch1/` was not modified.

## Exact commands
Batch build (prior worker; reused after byte-verification):
```
python3 ~/workspace/eval2-kics-harness/final-build-batches.py
```
Batch scan (each batch N=2..5):
```
cd ~/workspace/kics && /usr/bin/time -f "WALL_SEC=%e PEAK_RSS_KB=%M" \
  ~/workspace/bin/kics scan -p ~/workspace/eval2-kics-harness/scratch/batchN \
  -o ~/workspace/aegis-engine/docs/audit/raw/final-eval/scanner-output/kics/batchN \
  --report-formats json --queries-path ./assets/queries --ignore-on-exit results --no-progress
```
(Wrapped in `~/workspace/eval2-kics-harness/final-run-batch.sh <N>`; batch1 ran under the same
invocation by the prior worker.)
Timing (per project, single run — documented deviation):
```
cd ~/workspace/kics && <timing_harness.time_project runs=1 timeout=600> of
  ~/workspace/bin/kics scan -p <corpus>/<id> -o <scratch>/timing-<id> \
    --report-formats json --queries-path ./assets/queries --ignore-on-exit results --no-progress
```
(Wrapped in `~/workspace/eval2-kics-harness/run-kics-timing.py`.)

## Batch composition (deterministic; reuses prior worker's scheme)
- 205 corpus project dirs sorted alphabetically (c001..c070, k001..k065, t001..t070),
  round-robin `batch = index % 5 + 1` → 5 × 41 projects.
- batch1: c001,c006,c011,…,k001,k006,…,t001,t006,…,t066 (index 0,5,10,…,200)
- batch2: c002,c007,…,t067   batch3: c003,c008,…,t068
- batch4: c004,c009,…,t069   batch5: c005,c010,…,t070
- Interleaving spreads t*/c*/k* formats and difficulty levels evenly across batches.
- COPIES at `<scratch>/batchN/corpus/<id>/...` (KICS Go walker does not descend into symlinked dirs).
  The literal `corpus/<id>/` path segment is required by the scorer regex `corpus/([^/]+)/`.
- Verified: batch1's 38 attributed ids ⊆ scheme batch1 (no re-scan needed); BATCHMAP.json in
  `~/workspace/eval2-kics-harness/scratch/` matches the recomputed scheme for all 5 batches;
  on-disk copies byte-identical to corpus, no symlinks.

## Per-batch results (wall time + peak RSS, from /usr/bin/time)
| batch | exit | WALL_SEC | PEAK_RSS_KB | files_scanned | queries w/ results | findings |
|-------|------|----------|-------------|---------------|---------------------|----------|
| 1 | 0 | 627.97 | 157304 | 58 | 150 | 298 |
| 2 | 0 | 415.14 | 189664 | 54 | 119 | 228 |
| 3 | 0 | 336.72 | 172688 | 52 | 138 | 232 |
| 4 | 0 | 358.20 | 168920 | 48 | 117 | 265 |
| 5 | 0 | 364.27 | 181132 | 59 | 145 | 304 |

Aggregate across all 5 batches (attribution-report.json): **1327 findings** (query × file pairs),
**669 queries with ≥1 file**, **177/205** projects with ≥1 attributed finding, **0** unattributable
file paths, **0** attributed ids outside the corpus.

Note: batches 2–5 ran as two parallel pairs (2‖3, 4‖5); all exits 0, RSS ~165–190 MB each.
box 7 GB → memory-safe. Timing varied with tenant load (loadavg ~8–9).

## Attribution verification (205/205)
- All finding file paths match the scorer regex `corpus/([^/]+)/` → every attributed id is a
  genuine corpus project; none outside the corpus.
- 28 ids with zero attributed findings: each has ≥1 KICS-supported file (azuredeploy.json,
  main.bicep, Pulumi.yaml, docker-compose.yml, main.tf) inside its batch root, which KICS walked
  with exit 0. Breakdown: 4× ARM (azuredeploy.json), 5× Bicep, 15× Pulumi.yaml, 1× docker-compose,
  3× Terraform (t058, t062, t069 — genuinely clean under this query set).
- files_scanned vs files-on-disk per batch matches within unsupported types
  (.txt/.sh/.py/.env — not KICS-scannable), so zero findings = "no findings", not "not scanned".
- **Result: all 205/205 projects were scanned and are attributable; 177/205 have ≥1 finding.**

## Timing (documented deviation: single run per project)
- 30 subset ids from `timing-subset.json`, one run each via `timing_harness.time_project(runs=1,
  timeout=600, cwd=~/workspace/kics/)`; recorded `{"single_run": s, "peak_rss_kb": KB, "exit_codes": [c]}`.
- Results (`TIMING.json`, 30/30 ids, shape verified, all exit 0):
  single_run min=4.94 s (c064, Pulumi-only), **median=28.91 s**, mean=51.04 s, max=153.84 s (t015);
  peak_rss_kb min/median=128052 KB, max=140876 KB.
- Caveats: (1) runs were sequential in one Python process, so `peak_rss_kb` is the harness's
  cumulative `RUSAGE_CHILDREN` max — the value can only rise across projects, not measure each in
  isolation (hence the flat 128052 for the first 20 ids and 140876 thereafter). Treat it as
  "max observed peak so far", not per-project peak. (2) Per-project wall time is dominated by
  KICS query-set load (~60 s baseline for terraform projects, ~5–9 s for single-file k8s/Pulumi,
  ~150 s for the large t001/t008/t015/t022 terraform projects), not by corpus size.
- Output: `scanner-output/kics/TIMING.json`.

## Failures
- None from KICS itself (all scans exit 0, files_failed_to_scan=0).
- Operational gap found on resume: the prior worker never created the top-level
  `batch1-results.json` copy (only `batch1/results.json`); copied it without touching the original.
