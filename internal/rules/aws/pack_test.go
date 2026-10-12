package aws

import (
	"testing"
)

func TestPack_HasExpectedRulesWithUniqueIDs(t *testing.T) {
	rules := Rules()
	// 282: 286 at v1.0.0 minus the 4 removed S3 hygiene rules
	// (558 object lock, 559 inventory, 602 notifications, 603 replication).
	if len(rules) != 282 {
		t.Fatalf("expected 282 rules, got %d", len(rules))
	}
	seen := map[string]bool{}
	var prev string
	for _, r := range rules {
		if r.ID() == "" || r.Title() == "" || r.Description() == "" {
			t.Fatalf("rule has empty metadata: %+v", r)
		}
		if seen[r.ID()] {
			t.Fatalf("duplicate rule ID: %s", r.ID())
		}
		seen[r.ID()] = true
		if prev != "" && r.ID() <= prev {
			t.Fatalf("rules not in ID order: %s after %s", r.ID(), prev)
		}
		prev = r.ID()
		switch r.Severity() {
		case "low", "medium", "high", "critical", "info":
		default:
			t.Fatalf("rule %s has invalid severity %q", r.ID(), r.Severity())
		}
	}
}
