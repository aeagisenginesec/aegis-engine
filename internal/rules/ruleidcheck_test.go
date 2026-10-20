package rules

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

// ruleIDCheckTestRegistry returns a small registry with two known rules.
// Using a hand-built registry keeps the test independent of the full
// 1,146-rule default registry.
func ruleIDCheckTestRegistry() *Registry {
	reg := NewRegistry()
	reg.Register(&fakeRuleForIDCheck{id: "AEGIS-AWS-001"})
	reg.Register(&fakeRuleForIDCheck{id: "AEGIS-AWS-004"})
	return reg
}

type fakeRuleForIDCheck struct{ id string }

func (f *fakeRuleForIDCheck) ID() string                       { return f.id }
func (f *fakeRuleForIDCheck) Title() string                    { return "test" }
func (f *fakeRuleForIDCheck) Description() string              { return "test" }
func (f *fakeRuleForIDCheck) Severity() ir.Severity            { return ir.SeverityHigh }
func (f *fakeRuleForIDCheck) AppliesTo(t string) bool          { return true }
func (f *fakeRuleForIDCheck) Check(r ir.Resource) []ir.Finding { return nil }

func TestCheckRuleID_Valid(t *testing.T) {
	reg := ruleIDCheckTestRegistry()
	if got := CheckRuleID("AEGIS-AWS-001", reg); got != RuleIDValid {
		t.Fatalf("valid ID classified as %v", got)
	}
	// The magic "all" suppression ID is always valid.
	if got := CheckRuleID("all", reg); got != RuleIDValid {
		t.Fatalf("'all' classified as %v", got)
	}
}

func TestCheckRuleID_Deprecated(t *testing.T) {
	reg := ruleIDCheckTestRegistry()
	// AEGIS-AWS-621 was removed by the post-audit deduplication.
	if got := CheckRuleID("AEGIS-AWS-621", reg); got != RuleIDDeprecated {
		t.Fatalf("deprecated ID classified as %v", got)
	}
	if got := CanonicalReplacement("AEGIS-AWS-621"); got != "AEGIS-AWS-316" {
		t.Fatalf("wrong canonical replacement: %q", got)
	}
}

func TestCheckRuleID_UnknownTypo(t *testing.T) {
	reg := ruleIDCheckTestRegistry()
	if got := CheckRuleID("AEGIS-AWS-9999", reg); got != RuleIDUnknown {
		t.Fatalf("typo ID classified as %v", got)
	}
	if got := CanonicalReplacement("AEGIS-AWS-9999"); got != "" {
		t.Fatalf("typo ID should have no canonical replacement, got %q", got)
	}
}

func TestValidateBaselineIDs_Mixed(t *testing.T) {
	reg := ruleIDCheckTestRegistry()
	b := &Baseline{
		Version: 1,
		Fingerprints: []Fingerprint{
			{RuleID: "AEGIS-AWS-001", Resource: "aws_s3_bucket.a", Attribute: "acl"},
			{RuleID: "AEGIS-AWS-621", Resource: "aws_s3_bucket.b", Attribute: "acl"},  // deprecated
			{RuleID: "AEGIS-AWS-9999", Resource: "aws_s3_bucket.c", Attribute: "acl"}, // typo
			{RuleID: "AEGIS-AWS-621", Resource: "aws_s3_bucket.d", Attribute: "acl"},  // duplicate entry: one diagnostic
		},
	}
	diags := ValidateBaselineIDs(b, reg)
	if len(diags) != 2 {
		t.Fatalf("expected 2 diagnostics, got %d: %+v", len(diags), diags)
	}
	// Sorted by ID: deprecated 621 before unknown 9999.
	if diags[0].ID != "AEGIS-AWS-621" || diags[0].Kind != RuleIDDeprecated {
		t.Fatalf("first diagnostic wrong: %+v", diags[0])
	}
	if diags[1].ID != "AEGIS-AWS-9999" || diags[1].Kind != RuleIDUnknown {
		t.Fatalf("second diagnostic wrong: %+v", diags[1])
	}
	// Deprecated diagnostic must name the canonical replacement and the doc.
	msg := diags[0].Message()
	if !strings.Contains(msg, "AEGIS-AWS-316") || !strings.Contains(msg, "DEPRECATED_RULE_IDS.md") {
		t.Fatalf("deprecated message missing migration pointer: %q", msg)
	}
	if !strings.Contains(msg, "has no effect") {
		t.Fatalf("deprecated message must state the entry has no effect: %q", msg)
	}
	// Unknown diagnostic must suggest a typo check, not a migration.
	if !strings.Contains(diags[1].Message(), "typo") {
		t.Fatalf("unknown message should suggest typo check: %q", diags[1].Message())
	}
}

func TestValidateBaselineIDs_AllValid(t *testing.T) {
	reg := ruleIDCheckTestRegistry()
	b := &Baseline{
		Version: 2,
		Entries: []BaselineEntry{
			{Fingerprint: Fingerprint{RuleID: "AEGIS-AWS-001", Resource: "r", Attribute: "a"}},
			{Fingerprint: Fingerprint{RuleID: "AEGIS-AWS-004", Resource: "r", Attribute: "a"}},
		},
	}
	if diags := ValidateBaselineIDs(b, reg); len(diags) != 0 {
		t.Fatalf("valid baseline produced diagnostics: %+v", diags)
	}
}

func TestValidateBaselineIDs_NilSafe(t *testing.T) {
	reg := ruleIDCheckTestRegistry()
	if diags := ValidateBaselineIDs(nil, reg); len(diags) != 0 {
		t.Fatalf("nil baseline produced diagnostics")
	}
	if diags := ValidateBaselineIDs(&Baseline{}, nil); len(diags) != 0 {
		t.Fatalf("nil registry produced diagnostics")
	}
}

func TestValidateSuppressedRuleIDs(t *testing.T) {
	reg := ruleIDCheckTestRegistry()
	ids := []string{"AEGIS-AWS-001", "all", "AEGIS-AZURE-298", "AEGIS-TYPO-1"}
	diags := ValidateSuppressedRuleIDs(ids, reg)
	if len(diags) != 2 {
		t.Fatalf("expected 2 diagnostics, got %d: %+v", len(diags), diags)
	}
	if diags[0].ID != "AEGIS-AZURE-298" || diags[0].Kind != RuleIDDeprecated {
		t.Fatalf("expected deprecated AEGIS-AZURE-298 first, got %+v", diags[0])
	}
	if diags[0].Canonical != "AEGIS-AZURE-155" {
		t.Fatalf("wrong canonical for AZURE-298: %q", diags[0].Canonical)
	}
	if diags[1].ID != "AEGIS-TYPO-1" || diags[1].Kind != RuleIDUnknown {
		t.Fatalf("expected unknown AEGIS-TYPO-1 second, got %+v", diags[1])
	}
	for _, d := range diags {
		if d.Source != "inline suppression" {
			t.Fatalf("wrong source: %q", d.Source)
		}
	}
}

func TestCollectSuppressedRuleIDs(t *testing.T) {
	resources := []ir.Resource{
		{SuppressedRules: []string{"AEGIS-AWS-001", "AEGIS-AWS-001", "all"}},
		{SuppressedRules: []string{"AEGIS-AWS-004"}},
		{},
	}
	got := CollectSuppressedRuleIDs(resources)
	want := []string{"AEGIS-AWS-001", "AEGIS-AWS-004", "all"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestDeprecatedIDsNeverSilentlyMigrate proves the core safety property:
// a baseline entry for a removed ID does not match findings from the
// canonical replacement rule. Matching stays exact on rule_id.
func TestDeprecatedIDsNeverSilentlyMigrate(t *testing.T) {
	b := &Baseline{
		Version:      1,
		Fingerprints: []Fingerprint{{RuleID: "AEGIS-AWS-621", Resource: "aws_redshift_cluster.x", Attribute: "logging"}},
	}
	b.buildIndex()
	// A finding from the canonical replacement must NOT be suppressed.
	f := ir.Finding{RuleID: "AEGIS-AWS-316", Resource: "aws_redshift_cluster.x"}
	f.Evidence.Attribute = "logging"
	if b.Matches(f) {
		t.Fatal("deprecated baseline entry matched canonical rule finding: silent migration")
	}
	// And the deprecated entry itself matches nothing real (rule no longer runs).
	f2 := ir.Finding{RuleID: "AEGIS-AWS-621", Resource: "aws_redshift_cluster.x"}
	f2.Evidence.Attribute = "logging"
	if !b.Matches(f2) {
		t.Fatal("baseline entry should still match its own fingerprint for bookkeeping")
	}
}

// TestDeprecatedMapCoversDocCount guards against the map drifting out of
// sync with docs/audit/DEPRECATED_RULE_IDS.md (65 entries: 39 post-audit
// + 3 outperform-mission + 9 multi-cloud quality audit + 1 follow-up
// + 13 Sprint-2 R4 FP-family).
func TestDeprecatedMapCoversDocCount(t *testing.T) {
	if len(deprecatedRuleIDs) != 65 {
		t.Fatalf("deprecated map has %d entries, doc lists 65", len(deprecatedRuleIDs))
	}
}

// TestDeprecatedMap_MultiCloudAudit pins the 9 IDs removed by the
// multi-cloud quality audit to their canonical replacements.
func TestDeprecatedMap_MultiCloudAudit(t *testing.T) {
	want := map[string]string{
		"AEGIS-AZR-004":   "AEGIS-AZURE-106",
		"AEGIS-AZURE-008": "AEGIS-AZURE-107",
		"AEGIS-AZURE-009": "AEGIS-AZURE-101",
		"AEGIS-AZURE-025": "AEGIS-AZURE-105",
		"AEGIS-AZURE-045": "AEGIS-AZURE-101",
		"AEGIS-AZURE-047": "AEGIS-AZURE-107",
		"AEGIS-AZURE-048": "AEGIS-AZURE-106",
		"AEGIS-AZURE-225": "AEGIS-AZURE-107",
		"AEGIS-GCP-063":   "AEGIS-GCP-018",
	}
	for id, canon := range want {
		if got := CanonicalReplacement(id); got != canon {
			t.Fatalf("%s: canonical = %q, want %q", id, got, canon)
		}
	}
	// Transitive pointer: 206's canonical (025) is itself deprecated now.
	if got := CanonicalReplacement("AEGIS-AZURE-206"); got != "AEGIS-AZURE-105" {
		t.Fatalf("206: canonical = %q, want AEGIS-AZURE-105", got)
	}
}

// TestDeprecatedMap_GCP122 pins the GCP-122 deprecation (follow-up to the
// multi-cloud quality audit: exact duplicate of GCP-032 with inconsistent
// High vs Medium severity; 032 kept as canonical).
func TestDeprecatedMap_GCP122(t *testing.T) {
	if got := CanonicalReplacement("AEGIS-GCP-122"); got != "AEGIS-GCP-032" {
		t.Fatalf("GCP-122: canonical = %q, want AEGIS-GCP-032", got)
	}
}
