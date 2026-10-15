package pulumi

import (
	"strings"
	"testing"
)

// Adapter audit 2026-10-14: a Pulumi.yaml whose resources: section exists
// but contains only entries WITHOUT a type: field parses to zero resources
// with zero diagnostics — a silent zero-findings scan on a file the user
// clearly intended to declare resources. The adapter already warns for a
// missing resources: section (TestNoResourcesSection) and for imperative
// programs it cannot analyze (pulumi_ts_test.go); a resources: section
// that yields nothing analyzable deserves the same honesty.
//
// This test pins the desired behavior: a warning naming the untyped
// entries. It is skipped until the adapter emits it; unskip when fixed.
func TestAuditUntypedResourcesWarn(t *testing.T) {
	// Fixed 2026-10-14: the adapter now warns naming the untyped entry
	// instead of silently dropping it (which produced a silent
	// zero-findings scan).
	src := `name: x
runtime: yaml
resources:
  weird:
    properties:
      foo: bar
`
	_, diags := parse(t, "Pulumi.yaml", src)
	for _, d := range diags {
		if d.Level == "warning" && strings.Contains(d.Message, "weird") {
			return // honest: the untyped entry is surfaced
		}
	}
	t.Fatalf("expected a warning about the untyped resource entry, got %+v", diags)
}
