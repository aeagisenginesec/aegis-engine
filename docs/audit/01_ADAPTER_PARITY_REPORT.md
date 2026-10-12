# 01 — Adapter Parity Verification (on fix branch)

**Mission:** Aegis Independent Competitive Validation and Benchmarking Mission
**Date:** 2026-10-12
**Phase:** 2 of 10

## 1. Approach

The full adapter semantic parity audit was completed previously and is documented in
`docs/ADAPTER_PARITY_REPORT.md` (331/331 subtests pass: 148 regression + 148 determinism
at 3× hash + 35 cross-format groups; 7 defects fixed; support matrix at
`benchmark/parity/support-matrix.json`, regenerable via `benchmark/parity/cmd/matrix`).

Per the mission spec, this phase does NOT redo the audit. It verifies the audit's
results still hold on the current fix branch (`fix/demo-defects-d1-d3`, HEAD `0c28621`),
which contains the D1/D2/D3 rule fixes committed after the audit.

## 2. Verification performed

| Check | Command | Result |
|---|---|---|
| Parity test suite on fix branch | `go test -count=1 ./cmd/aegis/ -run TestParity` | ✅ ok (2.07 s) |
| Full suite (no regressions from D-fixes) | `go test -count=1 ./...` | ✅ 32/32 packages pass |
| Race detector | `go test -race ./cmd/aegis/ ./internal/rules/... ./internal/adapter/...` | ✅ clean |

## 3. Impact of D1/D2/D3 fixes on the support matrix

The D-fixes changed **rule logic**, not adapter behavior:

- **D1** (AEGIS-AWS-666): extended IAM attachment coverage to `managed_policy_arns`
  and `*_policy_attachment` resources. Adapter output unchanged; the rule now reads
  attributes the adapters already produced. No support-matrix change (rule was already
  applicable to the same adapters; it now matches more resource shapes within them).
- **D2** (AEGIS-AWS-307): corrected KMS attribute lookup (`kms_key_arn` top-level).
  No adapter or matrix change.
- **D3** (AEGIS-AWS-343/344): unresolvable resource references now emit explicit
  `UNCERTAIN` diagnostics instead of silent skips. This **strengthens** the parity
  audit's "unknowns remain visible" criterion; no matrix membership change.

**Conclusion:** the parity audit's findings stand on the fix branch. The support matrix
(`benchmark/parity/support-matrix.json`, 9 adapters × 1,185 rules) was generated
pre-D-fix; since no adapter applicability changed, regeneration is not required, but
Phase 3 (rule inventory) re-derives rule metadata from the live registry independently.

## 4. Reference

Full audit: `docs/ADAPTER_PARITY_REPORT.md`.
Fixtures: `benchmark/parity/fixtures/` (148, each with `expect.json`).
Machine-readable summary: `benchmark/parity/test-summary.json`.
Repro: `cd ~/workspace/aegis-engine && go test ./cmd/aegis/ -run TestParity -v`.

**No universal multi-format parity is claimed** — coverage is exactly the 148 tested
equivalence cases, as documented in the audit report.
