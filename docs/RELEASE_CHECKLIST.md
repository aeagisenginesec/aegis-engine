# Aegis v1.0.0 Release Checklist

## Pre-release verification

- [ ] `go test ./...` — all packages pass
- [ ] `go test -race ./...` — no data races
- [ ] `go vet ./...` — clean
- [ ] `gofmt -l .` — no unformatted files
- [ ] `aegis quality-gate` — all 5 checks PASS
- [ ] `aegis doctor` — all self-checks pass, correct rule count
- [ ] Fuzz parsers 60s+ with no crashes (`go test -fuzz=FuzzParseModule`)
- [ ] Reproducible build verified (two builds, identical sha256)
- [ ] SBOM generated and current (`SBOM.md`)
- [ ] CHANGELOG.md updated with all changes since last release
- [ ] `aegis --version` reports correct version

## Detection quality

- [ ] Labeled corpus: precision ≥ 0.95, recall ≥ 0.95
- [ ] Held-out benchmark F1 within expected variation of baseline
- [ ] No rules with precision < 0.80 without documented justification
- [ ] Regression fixtures pass for all critical rules

## Performance

- [ ] vuln-200 median < 1,000ms (perf gate)
- [ ] Remediation enrichment < 5ms (isolated benchmark)
- [ ] No p95 regression > 150% of baseline

## Documentation

- [ ] `docs/THREAT_MODEL.md` current
- [ ] `docs/LIMITATIONS.md` current and honest
- [ ] `docs/ARCHITECTURE.md` matches implementation
- [ ] `docs/CI_INTEGRATION.md` examples tested
- [ ] `docs/BASELINES.md` matches baseline format
- [ ] `docs/RELEASE_NOTES_v1.0.0.md` written
- [ ] README.md quick-start commands verified

## Release artifacts

- [ ] Binary built with version ldflags:
  `go build -ldflags "-X aegis/internal/version.BuildDate=$(date -u +%Y-%m-%d) -X aegis/internal/version.Commit=$(git rev-parse --short HEAD)" -o aegis ./cmd/aegis`
- [ ] SHA256 checksums published for all artifacts
- [ ] Release signed (cosign/gpg) where feasible
- [ ] ZIP contains: binary, README.md, CHANGELOG.md, docs/, examples/
- [ ] ZIP excludes: .git, test binaries, build scratch

## Post-release

- [ ] Benchmark commands, tool versions, dataset revisions published
- [ ] Raw benchmark results available in `benchmark/`
- [ ] Known issues filed for deferred work
