package rules

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

func TestRemediationFor_DetailedEntry(t *testing.T) {
	fix, refs := RemediationFor("AEGIS-AWS-001")
	if !strings.Contains(fix, "server_side_encryption_configuration") {
		t.Errorf("AEGIS-AWS-001 fix should mention server_side_encryption_configuration, got: %q", fix[:80])
	}
	if len(refs) == 0 {
		t.Error("AEGIS-AWS-001 should have reference URLs")
	}
}

func TestRemediationFor_CriticalEntries(t *testing.T) {
	critical := []string{
		"AEGIS-AWS-003", "AEGIS-AWS-006", "AEGIS-AWS-101", "AEGIS-AWS-104",
		"AEGIS-AWS-202", "AEGIS-AWS-501", "AEGIS-AWS-502", "AEGIS-AWS-534",
		"AEGIS-AWS-629", "AEGIS-GCP-001", "AEGIS-K8S-001",
	}
	for _, id := range critical {
		fix, refs := RemediationFor(id)
		if fix == "" {
			t.Errorf("%s: empty remediation", id)
		}
		if len(refs) == 0 {
			t.Errorf("%s: no references", id)
		}
	}
}

func TestRemediationFor_FallbackNeverEmpty(t *testing.T) {
	// Every rule in the registry must get non-empty guidance.
	for _, r := range DefaultRegistry().All() {
		fix, refs := RemediationFor(r.ID())
		if fix == "" {
			t.Errorf("%s: fallback remediation is empty", r.ID())
		}
		if len(refs) == 0 {
			t.Errorf("%s: fallback references are empty", r.ID())
		}
	}
}

func TestEnrichRemediation(t *testing.T) {
	findings := []ir.Finding{
		{RuleID: "AEGIS-AWS-001", Title: "S3 bucket without server-side encryption"},
		{RuleID: "AEGIS-AWS-999", Title: "Nonexistent rule"},
	}
	out := EnrichRemediation(findings)
	for i, f := range out {
		if f.Remediation == "" {
			t.Errorf("finding %d (%s): empty remediation after enrich", i, f.RuleID)
		}
		if len(f.References) == 0 {
			t.Errorf("finding %d (%s): empty references after enrich", i, f.RuleID)
		}
	}
}
