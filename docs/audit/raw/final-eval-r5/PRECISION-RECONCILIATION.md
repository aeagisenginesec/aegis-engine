# R5 Precision Reconciliation — carried "FP" verdicts re-verified (closeout)

Date: 2026-10-20 · Scope: measurement only. **No rule, adapter, or test
was changed because of anything here** (blind-set integrity). Findings
feed the open-issues list in `docs/audit/26_AEGIS_FINAL_STATE.md`.

## The murk

`CLOSEOUT-RUN.md` joins the closeout sweep's 1,192 unmatched findings
to the prior round's adjudication (`labels/fp-adjudicated-aegis.json`)
on (project, rule, file): 721 carried **FP** / 37 TP / 434 HYGIENE,
giving point precision 71 / (71 + 721) = **0.090**. But the same run
notes the unmatched mass reads as mostly real-but-unlabeled. Both
cannot be true under one definition of "FP" — so the carried FP
verdicts were re-verified against the corpus source.

Reproduction note: the join was rebuilt from `score_r5.py` machinery
over `scanner-output/aegis-closeout/` and reproduced the closeout
numbers exactly (findings 1,263, hygiene 17, TP 71, FN 57, unmatched
1,192, carried 721/37/434, zero unadjudicated newcomers).

## Method

- Stratified hand sample: **35 carried-FP items across 16 rules**
  (all top-volume families, all AWS-001/K8S-027 signature firings
  available, plus long-tail singles). Each verified against the cited
  corpus source: the finding is CONFIRMED-FP only if the flagged
  condition is factually absent/misread; LABEL-NOISE if the flagged
  condition factually holds (regardless of materiality judgments).
- Full censuses (not samples) for the four families that matter:
  AWS-001 (6), K8S-006 (32), K8S-029 (53), K8S-030 (25) — 116 carried
  items, every firing checked container-exact against parsed YAML.
- Standard applied: the platform-default doctrine used across this
  repo's adjudications — an absence-based claim is factually correct
  iff the platform default is the flagged state.

## Results

Sample (35): **3 CONFIRMED-FP / 32 LABEL-NOISE.** Every confirmed FP
is AWS-001. The other 32 justifications are materiality judgments
("pedantry", "not a security control", "by-design public") over
findings that describe their configs accurately — verified in source:
world-open 443 SGs (AWS-004 ×2), Deny-with-no-IP-rules Key Vaults
(AZURE-205 ×2), shared-key-by-default storage (AZURE-031), no-limits /
no-seccomp / no-drop / no-NetworkPolicy workloads (K8S-006/029/030/031),
tag-pinned images (K8S-032), label/STOPSIGNAL/COPY-lint Dockerfiles
(DOCKER-017/018/022, single-stage), and similar.

Censuses:
- **AWS-001: 6/6 CONFIRMED-FP.** All six projects (r5005, r5022,
  r5048, r5054, r5058, r5060) contain zero SSE configuration; the
  buckets rely on the platform default, which is SSE-S3
  encryption-on (S3 default since Jan 2023). "Without server-side
  encryption" is factually wrong for all six. This is the family's
  known open signature — recorded, not fixed (blind-set integrity).
- **K8S-006: 0/32 confirmed** (36 firings). **K8S-029: 0/53** (59
  firings — the adjudicator's "RuntimeDefault is the Kubernetes
  default" premise is itself platform-wrong; the flagged containers
  genuinely set no seccompProfile). **K8S-030: 0/25** (27 firings).
- Twin caveat: 7 K8S-006/030 firings are *twin-ambiguous* — the corpus
  plants a vulnerable and a hardened Deployment with the **same name**
  in one file (e.g. r5209 `shop-2e5ce5`); the firing is true of the
  vulnerable instance, but the resource identity
  (`k8s_Deployment.shop-2e5ce5`) cannot distinguish the twins. Counted
  LABEL-NOISE (a true referent exists); the identity collision itself
  is logged as a reporting-quality open issue.
- K8S-027's 6 closeout firings are carried **HYGIENE**, not FP — the
  signature is outside the 721 entirely.

## Corrected precision statement

Unique carried-FP items verified against source: 142 (35 sample +
116 census − 9 overlap). Confirmed factual FPs among them: **6, all
one family (AWS-001)**. Zero factual FPs in 136 verified non-AWS-001
items → rule-of-three 95% upper bound ≈ 2.2% on the 579 unverified
remainder → ≤ ~13 residual.

- True factual FP among the 721: **≈ 6–19** (not 721).
- Corrected point precision (scorer's definition,
  TP / (TP + FP)): 71 / (71 + 6…19) = **0.79–0.92** (vs carried 0.090).
- Factual precision over all non-hygiene closeout findings, counting
  the 37 carried-TP and the label-noise findings as the real findings
  they are: (71 + 37 + 721 − FP) / 829 ≈ **0.98**.

The 0.090 figure is an artifact of an adjudication standard that
scored "real but immaterial / by-design / not-in-ground-truth" as FP.
Under a factual standard the engine's blind-corpus precision is
~0.8–0.9 on the scorer's definition and ~0.98 counting everything it
verifiably gets right; its blind-corpus problem is **recall (0.555)
and coverage**, not correctness of what fires.
