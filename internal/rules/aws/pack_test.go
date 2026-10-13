package aws

import (
	"testing"
)

func TestPack_HasExpectedRulesWithUniqueIDs(t *testing.T) {
	rules := Rules()
	// 473: 282 baseline + 200 deep-expansion rules (650-849) + AWS-850
	// + AWS-851..855 (CloudTrail/CloudWatch, CMK refinement)
	// − 684, 692, 702 (removed: false premise / duplicate of 546).
	if len(rules) != 473 {
		t.Fatalf("expected 475 rules, got %d", len(rules))
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
