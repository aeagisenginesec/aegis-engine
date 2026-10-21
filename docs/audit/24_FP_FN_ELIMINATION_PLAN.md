# Plan 24 — FP/FN Elimination: immediate fixes + permanent apparatus

Date: 2026-10-20 · Baseline: R4 final eval (adjudicated, committed)
Baseline scoreboard: **Precision 1.000 · Recall 0.941 · F1 0.970 · FP 0 · FN 8** (136 GT points)

## Honest premise
Zero FP/FN is not a state you reach once — detection faces a moving target
(new services, new IaC constructs, new adapters). "Fixed forever" means a
system that drives the numbers to zero on every frozen corpus and keeps them
there as the corpus grows. That system is specified below.

## Part 1 — Fix immediately
1. **Definitive FN list.** Re-run `score.py` against the frozen R4 outputs in
   FN-report mode; enumerate the exact 8 missed GT cases. Classify each by
   root cause: (a) adapter gap — construct invisible to the parser;
   (b) rule gap — no rule exists; (c) semantic gap — rule exists but its
   condition misses this code shape.
2. **Fix by class, not by case.** The R4 campaign proved family-level fixes
   win (absence-based FP family: AZURE-145/195/108/169/313; adapter parity:
   e961f43). Apply the same approach:
   - Bicep adapter parity pass (weakest recall, 0.46): loops, nested
     deployments, parameter/variable indirection, symbolic names.
   - CloudFormation parity pass (recall 0.72): parameter-referenced secrets,
     intrinsic functions (Ref/Sub/If), nested stacks.
   - ARM (recall 0.846): remaining nested-property promotion gaps.
3. **Close out FP candidates.** The raw R4 pass left 2,308 unadjudicated FP
   candidates. Adjudicate the remainder in severity order (critical/high
   first). Every confirmed FP pattern gets a family fix + regression case.
4. **Re-score and freeze.** Full R4 protocol re-run after fixes.
   Exit criteria: **FN = 0 and FP = 0 on the R4 corpus**; commit as the new
   frozen baseline before any further rule work.

## Part 2 — Keep it fixed forever (the apparatus)
1. **Twin-fixture rule for every rule.** No rule merges without a positive
   (vulnerable) AND a negative (compliant) fixture. Kills absence-based FPs
   at birth — historically the largest FP family.
2. **Zero-drift CI gate.** The frozen corpus + all regression cases run in
   CI (`internal/regression`); any precision or recall drop, however small,
   fails the build. No exceptions, no "fix later."
3. **Cross-format parity matrix.** The same vulnerability expressed in
   Terraform / CloudFormation / ARM / Bicep / Pulumi / K8s / Compose must
   fire the same rule ID. Automated parity suite; a parity miss is an FN
   by definition and blocks merge.
4. **Compliant-code FP budget = 0.** A clean, compliant fixture suite must
   produce zero findings in CI. (Historical datapoint: 2 FPs on the
   vuln-200-era compliant fixture — the gate makes that a build failure,
   not a statistic.)
5. **Differential scanning loop (monthly).** Aegis + Checkov + KICS + Trivy
   over fresh corpora (TerraGoat, new generated fixtures, real-world OSS
   IaC). Every cross-scanner disagreement is adjudicated; confirmed cases
   enter ground truth. This finds FNs no single scanner knows it has.
6. **Sealed, growing ground truth.** Each evaluation round pre-registers
   and seals its corpus before any scanner runs (the R3/R4 pattern).
   Target: 136 → 500+ GT points within two rounds, weighted toward the
   weak formats (Bicep, CFN) and new services.
7. **Release rule.** No release ships unless the current frozen eval reads
   FP = 0 and FN = 0, the parity matrix is green, and the compliant
   fixture is silent.

## Sequencing
- Sprint 1: steps 1–2 (FN list + Bicep/CFN family fixes)
- Sprint 2: step 3 (FP candidate close-out) + step 4 (re-freeze)
- Sprint 3: apparatus items 1–4 wired into CI
- Ongoing: items 5–7 as standing process
