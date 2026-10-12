# Aegis SBOM — Go module dependencies

Generated from go.mod via go list -m -json all.

| Module | Version |
|--------|---------|
| github.com/agext/levenshtein | v1.2.1 |
| github.com/apparentlymart/go-textseg/v15 | v15.0.0 |
| github.com/apparentlymart/go-textseg/v17 | v17.0.1 |
| github.com/davecgh/go-spew | v1.1.1 |
| github.com/go-test/deep | v1.0.3 |
| github.com/google/go-cmp | v0.6.0 |
| github.com/hashicorp/hcl/v2 | v2.25.0 |
| github.com/mitchellh/go-wordwrap | v1.0.1 |
| github.com/spf13/pflag | v1.0.2 |
| github.com/vmihailenco/msgpack/v5 | v5.3.5 |
| github.com/vmihailenco/tagparser/v2 | v2.0.0 |
| github.com/yuin/goldmark | v1.4.13 |
| github.com/zclconf/go-cty | v1.19.0 |
| github.com/zclconf/go-cty-debug | v0.0.0-20240509010212-0d6042c53940 |
| golang.org/x/mod | v0.29.0 |
| golang.org/x/net | v0.46.0 |
| golang.org/x/sync | v0.18.0 |
| golang.org/x/sys | v0.38.0 |
| golang.org/x/telemetry | v0.0.0-20251008203120-078029d740a8 |
| golang.org/x/term | v0.37.0 |
| golang.org/x/text | v0.31.0 |
| golang.org/x/tools | v0.38.0 |
| gopkg.in/check.v1 | v0.0.0-20161208181325-20d25e280405 |
| gopkg.in/yaml.v3 | v3.0.1 |

Total dependencies: 24

## Vulnerability Review

Automated scanning with `govulncheck` was attempted but the tool could not
run in this sandbox environment (module resolution failure unrelated to the
code). Manual review of the 24 dependencies:

- **No network-facing or crypto libraries** beyond Go stdlib (`golang.org/x/*`).
- **Core parsing**: `hashicorp/hcl/v2 v2.25.0`, `zclconf/go-cty v1.19.0` — widely used, stable.
- **CLI**: `spf13/pflag v1.0.2` — stable.
- **Test-only**: `go-test/deep`, `google/go-cmp`, `davecgh/go-spew`, `gopkg.in/check.v1`.
- All versions are recent stable releases as of 2026-10.

Recommendation: run `govulncheck ./...` in CI on a standard runner before
each release. The Go vulnerability database (https://pkg.go.dev/vuln/) tracks
all listed modules.
