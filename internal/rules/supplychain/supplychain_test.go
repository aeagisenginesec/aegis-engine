package supplychain

import (
	"testing"

	"aegis/internal/ir"
)

// providerRes builds the synthetic terraform_provider resource per the CLI
// contract.
func providerRes(source, constraint string) ir.Resource {
	attrs := map[string]ir.Value{}
	if constraint != "" {
		attrs["version_constraint"] = ir.Value{Raw: constraint, Known: true, Span: ir.Span{File: "v.tf", StartLine: 3}}
	}
	return ir.Resource{
		Type: "terraform_provider", Name: source, Provider: "terraform",
		Attributes: attrs,
		Span:       ir.Span{File: "v.tf", StartLine: 1},
	}
}

// advisoryRes builds the synthetic aegis_advisory resource per the CLI
// contract.
func advisoryRes(id, pkg, affected, severity string) ir.Resource {
	attrs := map[string]ir.Value{
		"package":  {Raw: pkg, Known: true},
		"affected": {Raw: affected, Known: true},
	}
	if severity != "" {
		attrs["severity"] = ir.Value{Raw: severity, Known: true}
	}
	return ir.Resource{
		Type: "aegis_advisory", Name: id, Provider: "aegis",
		Attributes: attrs,
	}
}

func runSC(t *testing.T, resources []ir.Resource) []ir.Finding {
	t.Helper()
	var out []ir.Finding
	for _, r := range Rules() {
		if cr, ok := r.(ir.CrossResourceRule); ok {
			out = append(out, cr.CheckAll(resources)...)
			continue
		}
		for _, res := range resources {
			if r.AppliesTo(res.Type) {
				out = append(out, r.Check(res)...)
			}
		}
	}
	return out
}

func TestVulnerableVersionFires(t *testing.T) {
	fs := runSC(t, []ir.Resource{
		providerRes("hashicorp/aws", "5.1.0"),
		advisoryRes("CVE-2024-1234", "hashicorp/aws", ">= 4.0.0, < 5.2.0", "high"),
	})
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(fs), fs)
	}
	f := fs[0]
	if f.RuleID != "AEGIS-SC-001" {
		t.Errorf("rule id = %q", f.RuleID)
	}
	if f.Severity != ir.SeverityHigh {
		t.Errorf("severity = %q, want high", f.Severity)
	}
	if f.Resource != "terraform_provider.hashicorp/aws" {
		t.Errorf("resource = %q", f.Resource)
	}
	if f.Evidence.Attribute != "version" {
		t.Errorf("evidence attribute = %q", f.Evidence.Attribute)
	}
}

func TestFixedVersionSilent(t *testing.T) {
	fs := runSC(t, []ir.Resource{
		providerRes("hashicorp/aws", "5.2.0"),
		advisoryRes("CVE-2024-1234", "hashicorp/aws", ">= 4.0.0, < 5.2.0", "high"),
	})
	if len(fs) != 0 {
		t.Errorf("got %d findings, want 0: %+v", len(fs), fs)
	}
}

// TestSC001_FixedVersionQuiet is the explicit rule-ID-tagged negative for
// AEGIS-SC-001: a provider version outside every advisory's affected range
// produces no finding from this rule alone.
func TestSC001_FixedVersionQuiet(t *testing.T) {
	resources := []ir.Resource{
		providerRes("hashicorp/aws", "5.2.0"),
		advisoryRes("CVE-2024-1234", "hashicorp/aws", ">= 4.0.0, < 5.2.0", "high"),
	}
	var fs []ir.Finding
	for _, r := range Rules() {
		if r.ID() != "AEGIS-SC-001" {
			continue
		}
		if cr, ok := r.(ir.CrossResourceRule); ok {
			fs = append(fs, cr.CheckAll(resources)...)
		}
	}
	if len(fs) != 0 {
		t.Fatalf("AEGIS-SC-001: expected 0 findings for fixed version, got %+v", fs)
	}
}

func TestRangeConstraintNoFinding(t *testing.T) {
	for _, c := range []string{">= 4.0.0", "~> 4.2", ">= 4.0.0, < 6.0.0", "*"} {
		fs := runSC(t, []ir.Resource{
			providerRes("hashicorp/aws", c),
			advisoryRes("CVE-2024-1234", "hashicorp/aws", ">= 4.0.0, < 5.2.0", "high"),
		})
		if len(fs) != 0 {
			t.Errorf("constraint %q: got %d findings, want 0", c, len(fs))
		}
	}
}

func TestUnknownVersionNoFinding(t *testing.T) {
	// absent version_constraint attribute
	fs := runSC(t, []ir.Resource{
		providerRes("hashicorp/aws", ""),
		advisoryRes("CVE-2024-1234", "hashicorp/aws", ">= 4.0.0, < 5.2.0", "high"),
	})
	if len(fs) != 0 {
		t.Errorf("got %d findings, want 0", len(fs))
	}
	// unknown (unresolved) version value
	r := providerRes("hashicorp/aws", "")
	r.Attributes["version_constraint"] = ir.UnknownValue(ir.Span{File: "v.tf"})
	fs = runSC(t, []ir.Resource{
		r,
		advisoryRes("CVE-2024-1234", "hashicorp/aws", ">= 4.0.0, < 5.2.0", "high"),
	})
	if len(fs) != 0 {
		t.Errorf("unknown version: got %d findings, want 0", len(fs))
	}
}

func TestPackageMismatchNoFinding(t *testing.T) {
	fs := runSC(t, []ir.Resource{
		providerRes("hashicorp/aws", "5.1.0"),
		advisoryRes("CVE-2024-9999", "hashicorp/azurerm", ">= 1.0.0, < 9.9.9", "critical"),
	})
	if len(fs) != 0 {
		t.Errorf("got %d findings, want 0", len(fs))
	}
}

func TestSeverityMapping(t *testing.T) {
	cases := []struct {
		in   string
		want ir.Severity
	}{
		{"critical", ir.SeverityCritical},
		{"high", ir.SeverityHigh},
		{"medium", ir.SeverityMedium},
		{"low", ir.SeverityLow},
		{"", ir.SeverityHigh},      // default
		{"bogus", ir.SeverityHigh}, // default
		{"CRITICAL", ir.SeverityCritical},
	}
	for _, c := range cases {
		fs := runSC(t, []ir.Resource{
			providerRes("hashicorp/aws", "5.1.0"),
			advisoryRes("CVE-2024-1234", "hashicorp/aws", "< 9.0.0", c.in),
		})
		if len(fs) != 1 {
			t.Fatalf("severity %q: got %d findings, want 1", c.in, len(fs))
		}
		if fs[0].Severity != c.want {
			t.Errorf("severity %q -> %q, want %q", c.in, fs[0].Severity, c.want)
		}
	}
}

func TestMalformedAdvisoryIgnored(t *testing.T) {
	// advisory missing package: unusable, must not match or panic
	bad := advisoryRes("CVE-1", "", ">= 1.0.0", "high")
	delete(bad.Attributes, "package")
	fs := runSC(t, []ir.Resource{
		providerRes("hashicorp/aws", "5.1.0"),
		bad,
		advisoryRes("CVE-2024-1234", "hashicorp/aws", ">= 4.0.0, < 5.2.0", "high"),
	})
	if len(fs) != 1 {
		t.Errorf("got %d findings, want 1 (malformed advisory ignored)", len(fs))
	}
}

func TestDeterminism(t *testing.T) {
	resources := []ir.Resource{
		providerRes("hashicorp/random", "3.5.0"),
		providerRes("hashicorp/aws", "5.1.0"),
		advisoryRes("CVE-2024-2222", "hashicorp/random", "< 3.6.0", "medium"),
		advisoryRes("CVE-2024-1234", "hashicorp/aws", ">= 4.0.0, < 5.2.0", "high"),
	}
	a := runSC(t, resources)
	// reversed input order must produce identical findings
	b := runSC(t, []ir.Resource{resources[3], resources[2], resources[1], resources[0]})
	if len(a) != 2 || len(b) != 2 {
		t.Fatalf("got %d/%d findings, want 2/2", len(a), len(b))
	}
	for i := range a {
		if a[i].RuleID != b[i].RuleID || a[i].Resource != b[i].Resource ||
			a[i].Evidence.Actual != b[i].Evidence.Actual || a[i].Severity != b[i].Severity {
			t.Errorf("non-deterministic findings:\n%+v\n%+v", a, b)
		}
	}
}

func TestPackRules(t *testing.T) {
	rs := Rules()
	if len(rs) != 9 {
		t.Errorf("Rules() returned %d rules, want 9", len(rs))
	}
	if len(rs) > 0 && rs[0].ID() != "AEGIS-SC-001" {
		t.Errorf("Rules()[0] = %q, want AEGIS-SC-001", rs[0].ID())
	}
}
