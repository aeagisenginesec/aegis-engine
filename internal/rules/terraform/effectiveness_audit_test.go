package terraform

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

// Effectiveness audit (ITEM 3): this pack had no probe-only gaps — every
// rule is covered by the black-box probe (see docs/audit/14_RULE_EFFECTIVENESS.md
// and docs/audit/raw/rule-effectiveness.csv) and/or an existing pos+neg test,
// so no per-rule replay test was needed here. This smoke test pins the
// pack registry invariants the audit relies on.
func TestEffectivenessAudit_PackRegistry(t *testing.T) {
	rules := Rules()
	if len(rules) == 0 {
		t.Fatal("pack registry is empty")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		if r.ID() == "" || !strings.HasPrefix(r.ID(), "AEGIS-") {
			t.Errorf("bad rule ID %q", r.ID())
		}
		if seen[r.ID()] {
			t.Errorf("duplicate rule ID %s", r.ID())
		}
		seen[r.ID()] = true
		switch r.Severity() {
		case ir.SeverityCritical, ir.SeverityHigh, ir.SeverityMedium, ir.SeverityLow, ir.SeverityInfo:
		default:
			t.Errorf("rule %s has invalid severity %q", r.ID(), r.Severity())
		}
		if r.Title() == "" || r.Description() == "" {
			t.Errorf("rule %s has empty title/description", r.ID())
		}
	}
}
