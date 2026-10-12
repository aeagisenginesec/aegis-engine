package rules

import (
	"testing"

	"aegis/internal/ir"
	"aegis/internal/rules/aws"
)

func TestComplianceFor_KnownRule(t *testing.T) {
	refs := ComplianceFor("AEGIS-AWS-001")
	if len(refs) == 0 {
		t.Fatal("expected compliance refs for AEGIS-AWS-001")
	}
	seen := map[string]bool{}
	for _, r := range refs {
		if r.Framework == "" || r.Control == "" {
			t.Errorf("empty framework/control in %+v", r)
		}
		seen[r.Framework] = true
	}
	for _, fw := range []string{"CIS-AWS-1.5", "NIST-800-53", "PCI-DSS-4.0"} {
		if !seen[fw] {
			t.Errorf("expected framework %s in refs for AEGIS-AWS-001", fw)
		}
	}
}

func TestComplianceFor_UnknownRule(t *testing.T) {
	if refs := ComplianceFor("AEGIS-AWS-999"); len(refs) != 0 {
		t.Errorf("expected no refs for unknown rule, got %v", refs)
	}
	if refs := ComplianceFor(""); len(refs) != 0 {
		t.Errorf("expected no refs for empty rule ID, got %v", refs)
	}
}

func TestComplianceFor_Deterministic(t *testing.T) {
	a := ComplianceFor("AEGIS-AWS-006")
	b := ComplianceFor("AEGIS-AWS-006")
	if len(a) != len(b) {
		t.Fatal("non-deterministic result length")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatal("non-deterministic refs")
		}
	}
}

func TestComplianceFrameworks(t *testing.T) {
	fws := ComplianceFrameworks()
	if len(fws) != 3 {
		t.Fatalf("expected 3 frameworks, got %v", fws)
	}
	// Must be sorted.
	for i := 1; i < len(fws); i++ {
		if fws[i-1] >= fws[i] {
			t.Errorf("frameworks not sorted: %v", fws)
		}
	}
}

func TestHasComplianceFramework(t *testing.T) {
	if !HasComplianceFramework("CIS-AWS-1.5") {
		t.Error("expected CIS-AWS-1.5 to be known")
	}
	if HasComplianceFramework("SOC2") {
		t.Error("SOC2 should not be a known framework")
	}
	if HasComplianceFramework("") {
		t.Error("empty framework should not be known")
	}
}

func TestFilterByCompliance(t *testing.T) {
	findings := []ir.Finding{
		{RuleID: "AEGIS-AWS-001", Title: "s3"}, // CIS + NIST + PCI
		{RuleID: "AEGIS-AWS-202", Title: "lb"}, // NIST + PCI only
		{RuleID: "AEGIS-AWS-999", Title: "x"},  // unmapped
	}
	out := FilterByCompliance(findings, "CIS-AWS-1.5")
	if len(out) != 1 {
		t.Fatalf("expected 1 CIS-mapped finding, got %d", len(out))
	}
	if out[0].RuleID != "AEGIS-AWS-001" {
		t.Errorf("wrong finding survived filter: %s", out[0].RuleID)
	}
	for _, r := range out[0].Compliance {
		if r.Framework != "CIS-AWS-1.5" {
			t.Errorf("filter should narrow refs to the framework, got %+v", r)
		}
	}
}

func TestFilterByCompliance_UnknownFramework(t *testing.T) {
	findings := []ir.Finding{{RuleID: "AEGIS-AWS-001"}}
	if out := FilterByCompliance(findings, "SOC2"); len(out) != 0 {
		t.Errorf("expected empty result for unknown framework, got %d", len(out))
	}
}

func TestEnrichCompliance(t *testing.T) {
	findings := []ir.Finding{
		{RuleID: "AEGIS-AWS-001"},
		{RuleID: "AEGIS-AWS-999"},
	}
	out := EnrichCompliance(findings)
	if len(out[0].Compliance) == 0 {
		t.Error("expected refs attached to AEGIS-AWS-001")
	}
	if len(out[1].Compliance) != 0 {
		t.Error("expected no refs for unmapped rule")
	}
}

// Every mapped rule ID must exist in the AWS pack (catches typos).
func TestComplianceMap_RuleIDsExist(t *testing.T) {
	known := map[string]bool{}
	for _, r := range aws.Rules() {
		known[r.ID()] = true
	}
	for id := range complianceMap {
		if !known[id] {
			t.Errorf("compliance mapping references unknown rule %s", id)
		}
	}
}
