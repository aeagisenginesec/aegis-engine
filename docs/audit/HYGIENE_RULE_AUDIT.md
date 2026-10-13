# Hygiene-Rule Audit: DOCKER-017, DOCKER-018, K8S-015

**Date:** 2026-10-13
**Branch:** `mission/pulumi-recovery`
**Trigger:** Round-2 evaluation — these three rules produced 100 adjudicated
findings (DOCKER-018: 39, DOCKER-017: 39, K8S-015: 22), dominating Aegis's
FP tail and the precision gap vs Trivy.

**Principle:** No rule is demoted or disabled solely to improve a benchmark
score. Each decision below is justified on the rule's own security merits.
All three rules remain active at their current severities.

## DOCKER-017 — No maintainer label (Low)

- **What it checks:** Dockerfile lacks `LABEL maintainer=` or
  `org.opencontainers.image.authors`.
- **Security objective (stated):** ownership metadata aids triage when a
  vulnerability is found in the image.
- **Threat model:** none direct. A missing label enables no attack, weakens
  no control, and its absence causes no failure. This is metadata hygiene,
  not a vulnerability and barely a hardening recommendation.
- **Severity rationale:** Low is the floor; cannot go lower without a new
  informational tier.
- **Remediation value:** minimal for security outcomes. Useful for asset
  inventory, not for risk reduction.
- **Compliant behavior:** label present → quiet. Noncompliant: label absent
  → fires. Behavior is correct and deterministic.
- **Decision: KEEP, document as hygiene.** Weakest security justification of
  the three, but the rule is transparent about what it checks, fires
  correctly, and is already at minimum severity. Removing it now — right
  after it appeared in a benchmark tail — would be indistinguishable from
  benchmark gaming. Users who consider it noise can exclude it via
  `--config aegis.yaml` (`exclude_rules`).

## DOCKER-018 — No STOPSIGNAL directive (Low)

- **What it checks:** Dockerfile lacks `STOPSIGNAL`.
- **Security objective:** graceful shutdown semantics.
- **Threat model:** application handles only SIGINT (or a custom signal);
  without STOPSIGNAL the runtime sends SIGTERM, the app ignores it, the
  orchestrator escalates to SIGKILL → in-flight requests dropped,
  in-progress writes truncated, potential data corruption. For stateful
  workloads this is a real integrity risk.
- **Classification:** hardening recommendation (operational robustness with
  a data-integrity threat model).
- **Severity rationale:** Low is appropriate — the risk is conditional on
  the app's signal handling, which static analysis cannot determine.
- **Remediation value:** moderate; one-line fix, prevents a real failure mode.
- **Decision: KEEP at Low.** Legitimate hardening with a documented threat
  model. Fires correctly.

## K8S-015 — Container without readiness probe (Low)

- **What it checks:** container spec lacks `readinessProbe`.
- **Security objective:** availability — traffic routing correctness.
- **Threat model:** container receives traffic before it is ready →
  failed requests during startup, rolling updates, and recovery; cascading
  retries can amplify into partial outages.
- **Classification:** availability control. The round-2 FP adjudication
  explicitly validated this class: the first pass wrongly marked 195
  availability/detection findings as FP; re-adjudication under the
  protocol's "(including availability and detection controls)" criterion
  flipped 197 to TP. K8S-015 findings are **factually correct true
  positives** under the evaluation's own rules.
- **Severity rationale:** Low is appropriate — availability, not
  confidentiality/integrity.
- **Remediation value:** high for production workloads; probes are standard
  operational practice.
- **Decision: KEEP at Low.** Validated by independent adjudication. Removing
  or demoting it would contradict the evaluation evidence.

## Cross-cutting: signal vs noise

These rules are **correct but noisy**: they fire on nearly every minimal
Dockerfile/K8s manifest. That is a user-experience concern, not a
correctness defect, and the benchmark measures correctness (precision of
adjudicated findings), not noise level.

Noise control already exists and is now documented:
- `--config aegis.yaml` supports `severity_overrides` and `exclude_rules`
  (see `docs/PULUMI.md` § "Project config file").
- `--fail-on` sets the CI gate threshold; Low findings never fail a
  `high`-threshold gate by default.

No new filtering mechanism is introduced in this mission. No severities
changed. No rules disabled. Rule IDs stable.

## Summary

| Rule | Verdict | Reason |
|------|---------|--------|
| DOCKER-017 | Keep (Low) | Weak justification but transparent, correct, already minimal; removal now = gaming |
| DOCKER-018 | Keep (Low) | Real data-integrity threat model |
| K8S-015 | Keep (Low) | Adjudication-validated TP, real availability value |
