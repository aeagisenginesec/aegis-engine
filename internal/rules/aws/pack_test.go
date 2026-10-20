package aws

import (
	"testing"
)

func TestPack_HasExpectedRulesWithUniqueIDs(t *testing.T) {
	rules := Rules()
	// 474: pre-audit baseline 473 (282 baseline + 200 deep-expansion rules
	// (650-849) + AWS-850 + AWS-851..855, minus 684/692/702) + 1 AWS-856
	// (EC2 EOL image; concurrent addition, kept after audit review).
	// + 1 AWS-857 (CFN parameter secret default; R4 recall gap closure).
	// + 1 AWS-858 (SG database-port exposure; R4 Sprint-1 FN closure).
	if len(rules) != 476 {
		t.Fatalf("expected 476 rules, got %d", len(rules))
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
