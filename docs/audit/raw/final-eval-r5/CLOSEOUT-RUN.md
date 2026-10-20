# R5 Blind-Eval — Closeout Run (Sprint 3, report-only)

Re-run of the frozen R5 blind corpus with the FINAL engine after
Sprints 1–3. **Measurement only: no rule, adapter, or test was changed
because of anything in this run.** Misses are recorded as open issues
in `docs/audit/26_AEGIS_FINAL_STATE.md`; fixing on the blind set
would contaminate it.

## Binary

- Built from commit `67a01378f98bce3e95ea43cf5d00a14d96da9870`
  (post-Part-A source: Sprint 3 locks + ARM/Bicep adapter fixes +
  compliant gate)
- SHA-256: `15086b07cd13dbb6e6cec67b482f2496104efa32deadb3683dd35dc9d8c44cc4`
- Version: aegis 2.0.0

## Sweep

- Command per project (210 runs):
  `aegis scan corpus/<pid> --format=json > scanner-output/aegis-closeout/<pid>.json`
- Result: **210 OK / 0 failed**, all outputs valid JSON. Outputs live
  in the new `scanner-output/aegis-closeout/` subdir; prior rounds'
  outputs untouched. Scoring used `score_r5.py` via import (its
  `__main__` was never run; `scores-auto.json` and `labels/` are
  byte-identical to before this run).

## Scores — exactly as score_r5.py defines them

| metric | prior run (binary @3ed165a) | closeout run |
|---|---|---|
| auto TP | 70 | **71** |
| auto FN | 58 | **57** |
| recall (auto) | 0.547 | **0.555** |
| findings (non-hygiene) | 1,329 | 1,263 |
| hygiene excluded | 17 | 17 |
| unmatched (FP candidates) | 1,276 | **1,192** |
| total findings | 1,363 | 1,280 |

## Precision — carried adjudication (exact, not sampled)

Every one of the 1,192 closeout unmatched findings joins to a prior
human verdict in `labels/fp-adjudicated-aegis.json` on
(project, rule, file) — **zero unadjudicated newcomers**:

| carried verdict | prior run | closeout run |
|---|---|---|
| FP | 796 | 721 |
| TP (classifier/labeler misses) | 46 | 37 |
| HYGIENE | 434 | 434 |

Point precision (the prior round's definition: autoTP /
(autoTP + adjudicated FP)):

- prior: 70 / (70 + 796) = **0.081**, F1 **0.141**
- closeout: 71 / (71 + 721) = **0.090**, F1 **0.154** (recall 0.555)

The 84-finding unmatched drop decomposes exactly: −75 adjudicated
FPs (Sprint 2 duplicate deprecations + Docker final-stage gating)
and −9 adjudicated-TP findings that no longer fire (the same dup
merges — concept-level recall still rose, 70 → 71, so no matched
concept was lost). No deprecated Sprint 2 rule fires.

## Documented bug signatures — status in the closeout outputs

- **AZURE-169** (fired on `publicNetworkAccess='Disabled'` servers):
  23 → **5** firings, and all 5 verified against the corpus to be on
  servers with public access **Enabled** (r5005 TF
  `public_network_access_enabled = true`; r5088/r5103 Bicep
  `'Enabled'`; r5084/r5085 ARM — evidence string
  `public_network_access_enabled = true`, i.e. the Enabled of the
  two servers in each template). **The bug does not manifest.**
- **AZURE-145 / AZURE-195** (absence-fired "allows X" claims):
  13 → **0** each. **Do not manifest.**
- **AZURE-313** (title/detection mismatch): 12 → **0**.
- **AZURE-108**: 2 → **0**.
- **AWS-001** (SSE-default buckets): 6 → 6, unchanged. Open issue.
- **K8S-027**: 6 → 6, unchanged count. Open issue.

## FN profile (57 missed concepts — open issues, not fixes)

Dominated by classes the engine does not cover yet:

- `secret-hardcoded` — 31 (ARM/Bicep/CFN template parameter
  defaults, PostgreSQL flexible-server admin passwords, Pulumi
  config, Dockerfile ENV, .env files, K8s env literals)
- `sg-admin-public` — 5 · `ecr-public-policy` — 5 ·
  `compose-db-port-published` — 4 · `apigw-no-auth` — 3 ·
  `ebs-snapshot-public` — 3 · `k8s-cap-sys-admin` — 3 ·
  `kafka-plaintext` — 2

Full per-concept list: `scores/closeout-scores.json`.

## Reading of the result

On the blind corpus the engine's honest position is unchanged in
kind and slightly improved in degree: recall ~0.55 with adjudicated
point precision ~0.09 — the R5 corpus's "unmatched" mass is mostly
real-but-unlabeled findings and hygiene, which is why the FP count
stays high under this scorer even as every adjudicated factual-FP
family from the prior round (AZURE-169/145/195/313/108) is gone.
The R4 corpus (adjudicated ground truth, 136 concepts) remains the
accuracy bedrock: P 1.000 / R 0.941 → 1.000 after Sprints 1–2.
R5 says the frontier is coverage (secrets, snapshot/ECR/APIGW/MSK
classes), not correctness of what fires.
