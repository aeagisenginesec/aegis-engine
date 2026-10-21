package rules

import "testing"

// Sprint 2 deprecated 15 duplicate rules (audit doc 25) on top of the
// earlier post-audit deduplication, bringing deprecatedRuleIDs to 67
// entries. This lock keeps the deprecations permanent: a deprecated ID
// must never re-enter the default registry (that would resurrect
// double-reporting), and every non-empty canonical replacement must
// itself be registered (the migration pointer must not dangle).
func TestDeprecatedRulesStayUnregistered(t *testing.T) {
	if len(deprecatedRuleIDs) != 67 {
		t.Fatalf("deprecatedRuleIDs has %d entries, want 67 (docs/audit/DEPRECATED_RULE_IDS.md); "+
			"if a deprecation was added or reverted intentionally, update both", len(deprecatedRuleIDs))
	}
	registered := map[string]bool{}
	for _, r := range DefaultRegistry().All() {
		registered[r.ID()] = true
	}
	for id, canonical := range deprecatedRuleIDs {
		if registered[id] {
			t.Errorf("deprecated rule %s is registered in the default registry (duplicate-reporting lock)", id)
		}
		if canonical != "" && !registered[canonical] {
			t.Errorf("deprecated rule %s points at canonical %s, which is not registered", id, canonical)
		}
	}
	// The 15 Sprint 2 deprecations, pinned by name so a silent
	// un-deprecation of any one of them fails here even if the total
	// count is kept at 67 by swapping entries.
	sprint2 := []string{
		"AEGIS-AZURE-191", "AEGIS-AZURE-007", "AEGIS-AZURE-119", "AEGIS-AZURE-027",
		"AEGIS-AZURE-075", "AEGIS-AZURE-230", "AEGIS-AZURE-245",
		"AEGIS-AWS-547", "AEGIS-AWS-840", "AEGIS-AWS-418", "AEGIS-AWS-811",
		"AEGIS-AWS-812", "AEGIS-AWS-540", "AEGIS-GCP-048", "AEGIS-GCP-010",
	}
	for _, id := range sprint2 {
		if _, ok := deprecatedRuleIDs[id]; !ok {
			t.Errorf("Sprint 2 deprecation %s missing from deprecatedRuleIDs", id)
		}
	}
}
